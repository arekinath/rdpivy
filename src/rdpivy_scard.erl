%%
%% rdpproxy
%% remote desktop proxy
%%
%% Copyright 2022 Alex Wilson <alex@uq.edu.au>
%% The University of Queensland
%% All rights reserved.
%%
%% Redistribution and use in source and binary forms, with or without
%% modification, are permitted provided that the following conditions
%% are met:
%% 1. Redistributions of source code must retain the above copyright
%%    notice, this list of conditions and the following disclaimer.
%% 2. Redistributions in binary form must reproduce the above copyright
%%    notice, this list of conditions and the following disclaimer in the
%%    documentation and/or other materials provided with the distribution.
%%
%% THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
%% IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
%% OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
%% IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
%% INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
%% NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
%% DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
%% THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
%% (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
%% THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
%%

-module(rdpivy_scard).

-compile([{parse_transform, lager_transform}]).

-include_lib("rdp_proto/include/rdpp.hrl").
-include_lib("rdp_proto/include/rdpdr.hrl").
-include_lib("public_key/include/public_key.hrl").

-export([
    open/1,
    list_cards/1,
    connect/2
    ]).

-type card() :: #{
    guid => binary(),
    yk_version => {integer(), integer(), integer()},
    yk_serial => integer(),
    upns => [string()],
    reader => binary()
}.

-spec open(rdp_server:server()) -> {ok, rdp_scard:state()} | {error, term()}.
open(Srv) ->
    case rdp_server:get_vchan_pid(Srv, rdpdr_fsm) of
        {ok, RdpDr} ->
            case rdpdr_fsm:get_devices(RdpDr) of
                {ok, Devs} ->
                    case lists:keyfind(rdpdr_dev_smartcard, 1, Devs) of
                        false ->
                            {error, no_scard};
                        #rdpdr_dev_smartcard{id = DevId} ->
                            case rdpdr_scard:open(RdpDr, DevId, system) of
                                {ok, SC0} ->
                                    {ok, SC0};
                                Err ->
                                    lager:debug("failed to establish ctx: ~p",
                                        [Err]),
                                    Err
                            end
                    end;
                Err ->
                    lager:debug("failed to get rdpdr devs: ~p", [Err]),
                    Err
            end;
        _ ->
            {error, no_rdpdr}
    end.

-spec list_cards(rdp_scard:state()) -> {ok, [card()], rdp_scard:state()}.
list_cards(SC0) ->
    case rdpdr_scard:list_groups(SC0) of
        {ok, [Group0 | _], SC1} ->
            {ok, Readers, SC2} = rdpdr_scard:list_readers(Group0, SC1),
            get_rdr_infos(Readers, SC2);
        _ ->
            case rdpdr_scard:list_readers("SCard$DefaultReaders", SC0) of
                {ok, Readers, SC1} ->
                    get_rdr_infos(Readers, SC1);
                _ ->
                    {ok, Readers, SC1} = rdpdr_scard:list_readers("", SC0),
                    get_rdr_infos(Readers, SC1)
            end
    end.

-spec connect(binary(), rdp_scard:state()) -> {ok, pid(), rdp_scard:state()}.
connect(Rdr, SC0) ->
    case rdpdr_scard:connect(Rdr, shared, {t0_or_t1, optimal}, SC0) of
        {ok, Mode, SC1} ->
            {ok, [Piv | _]} = apdu_stack:start_link(element(1, Mode),
                [nist_piv, iso7816_chain, iso7816, {rdpdr_scard_apdu, [SC1]}]),
            {ok, Piv, SC1};
        Err ->
            Err
    end.

get_rdr_infos([], SC0) ->
    {ok, [], SC0};
get_rdr_infos([Rdr | Rest], SC0) ->
    case rdpdr_scard:connect(Rdr, shared, {t0_or_t1, optimal}, SC0) of
        {ok, Mode, SC1} ->
            case (catch get_rdr_info(Rdr, Mode, SC1)) of
                {ok, Info} ->
                    {ok, SC2} = rdpdr_scard:disconnect(leave, SC1),
                    case get_rdr_infos(Rest, SC2) of
                        {ok, RestInfo, SC3} ->
                            {ok, [Info | RestInfo], SC3};
                        Err ->
                            Err
                    end;
                Err ->
                    {ok, SC2} = rdpdr_scard:disconnect(leave, SC1),
                    get_rdr_infos(Rest, SC2)
            end;
        Err ->
            get_rdr_infos(Rest, SC0)
    end.

get_rdr_info(Rdr, Mode, SC0) ->
    {ok, [Piv | _]} = apdu_stack:start_link(element(1, Mode),
        [nist_piv, iso7816_chain, iso7816, {rdpdr_scard_apdu, [SC0]}]),
    ok = apdu_transform:begin_transaction(Piv),
    {ok, [{ok, #{version := V}}]} = apdu_transform:command(Piv, select),
    {ok, [{ok, #{guid := Guid}}]} = apdu_transform:command(Piv, read_chuid),
    <<GuidN:128/big>> = Guid,
    lager:debug("PIV applet v~B in ~p, GUID ~.16B", [V, Rdr, GuidN]),
    Info0 = #{reader => Rdr, guid => Guid},
    Info1 = case apdu_transform:command(Piv, yk_get_version) of
        {ok, [{ok, Version}]} ->
            Info0#{yk_version => Version};
        _ ->
            Info0
    end,
    Info2 = case apdu_transform:command(Piv, yk_get_serial) of
        {ok, [{ok, Serial}]} ->
            Info1#{yk_serial => Serial};
        _ ->
            Info1
    end,
    Info3 = Info2#{upns => get_card_upns(Piv)},
    lager:debug("info = ~p", [Info3]),
    apdu_transform:end_transaction(Piv),
    {ok, Info3}.

-define('szOID_NT_PRINCIPAL_NAME', {1,3,6,1,4,1,311,20,2,3}).

get_card_upns(Piv) ->
    get_card_upns([piv_auth, piv_sign, {retired, 1}, {retired, 2}], Piv).
get_card_upns([], Piv) -> [];
get_card_upns([Slot | Rest], Piv) ->
    case apdu_transform:command(Piv, {read_cert, Slot}) of
        {ok, [{ok, Cert}]} ->
            #'OTPCertificate'{tbsCertificate = TBS} = Cert,
            #'OTPTBSCertificate'{extensions = Exts} = TBS,
            SANExts = [E || E = #'Extension'{extnID = ID} <- Exts, ID =:= ?'id-ce-subjectAltName'],
            case SANExts of
                [#'Extension'{extnValue = SANs}] ->
                    Ders = [V || {otherName, #'AnotherName'{'type-id' = ?'szOID_NT_PRINCIPAL_NAME', value = V}} <- SANs],
                    Tlvs = [asn1rt_nif:decode_ber_tlv(Der) || Der <- Ders],
                    [Str || {{_Tag, Str}, <<>>} <- Tlvs, is_binary(Str)] ++ get_card_upns(Rest, Piv);
                _ ->
                    get_card_upns(Rest, Piv)
            end;
        _Err ->
            get_card_upns(Rest, Piv)
    end.
