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

-type slot() :: nist_piv:slot().

-type card() :: #{
    guid => binary(),
    yk_version => {integer(), integer(), integer()},
    yk_serial => integer(),
    upns => #{slot() => [string()]},
    public_keys => #{slot() => ebox:pubkey()},
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
            {ok, [Piv | _]} = apdu_stack:start_link(element(1, Mode),
                [nist_piv, iso7816_chain, iso7816, {rdpdr_scard_apdu, [SC1]}]),
            Res = (catch get_rdr_info(Rdr, Piv)),
            exit(Piv, kill),
            receive {'EXIT', Piv, _} -> ok end,
            {ok, SC2} = rdpdr_scard:disconnect(leave, SC1),
            case Res of
                {ok, Info} ->
                    case get_rdr_infos(Rest, SC2) of
                        {ok, RestInfo, SC3} ->
                            {ok, [Info | RestInfo], SC3};
                        Err ->
                            Err
                    end;
                _Err ->
                    get_rdr_infos(Rest, SC2)
            end;
        _Err ->
            get_rdr_infos(Rest, SC0)
    end.

get_rdr_info(Rdr, Piv) ->
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
    Info3 = get_card_cert_info(Piv, Info2),
    apdu_transform:end_transaction(Piv),
    {ok, Info3}.

-define('szOID_NT_PRINCIPAL_NAME', {1,3,6,1,4,1,311,20,2,3}).

get_card_cert_info(Piv, I0) ->
    Slots0 = [piv_card_auth, piv_auth, piv_sign, piv_key_mgmt],
    Slots1 = case apdu_transform:command(Piv, read_keyhist) of
        {ok, #{on_card_certs := N}} ->
            Slots0 ++ [{retired, N} || N <- lists:seq(1, N)];
        _ ->
            Slots0
    end,
    get_card_cert_info(Piv, Slots1, I0).

atomize_curve({namedCurve, secp256r1}) -> {namedCurve, secp256r1};
atomize_curve({namedCurve, ?'secp256r1'}) -> {namedCurve, secp256r1};
atomize_curve({namedCurve, secp384r1}) -> {namedCurve, secp384r1};
atomize_curve({namedCurve, ?'secp384r1'}) -> {namedCurve, secp384r1};
atomize_curve({namedCurve, secp521r1}) -> {namedCurve, secp521r1};
atomize_curve({namedCurve, ?'secp521r1'}) -> {namedCurve, secp521r1}.

get_card_cert_info(Piv, [], I0) -> I0;
get_card_cert_info(Piv, [Slot | Rest], I0) ->
    case apdu_transform:command(Piv, {read_cert, Slot}) of
        {ok, [{ok, Cert}]} ->
            #'OTPCertificate'{tbsCertificate = TBS} = Cert,
            #'OTPTBSCertificate'{subjectPublicKeyInfo = SPKI,
                                 extensions = Exts} = TBS,
            #'OTPSubjectPublicKeyInfo'{algorithm = PKA,
                                       subjectPublicKey = SPK} = SPKI,
            PubKey = case PKA of
                #'PublicKeyAlgorithm'{algorithm = ?'id-ecPublicKey',
                                      parameters = Curve = {namedCurve, _}} ->
                    ebox_crypto:compress({SPK, atomize_curve(Curve)});
                #'PublicKeyAlgorithm'{algorithm = ?'rsaEncryption'} ->
                    SPK
            end,
            PK0 = maps:get(public_keys, I0, #{}),
            PK1 = PK0#{Slot => PubKey},
            SANExts = [E || E = #'Extension'{extnID = ID} <- Exts,
                            ID =:= ?'id-ce-subjectAltName'],
            UPN0 = maps:get(upns, I0, #{}),
            UPN1 = case SANExts of
                [#'Extension'{extnValue = SANs}] ->
                    Ders = [V || {otherName, #'AnotherName'{'type-id' = ?'szOID_NT_PRINCIPAL_NAME', value = V}} <- SANs],
                    Tlvs = [asn1rt_nif:decode_ber_tlv(Der) || Der <- Ders],
                    UPNs = [Str || {{_Tag, Str}, <<>>} <- Tlvs, is_binary(Str)],
                    UPN0#{Slot => UPNs};
                _ ->
                    UPN0
            end,
            Valid0 = maps:get(valid_certs, I0, #{}),
            Valid1 = case (catch check_cert(Cert)) of
                {'EXIT', Why} ->
                    Valid0;
                _ ->
                    Valid0#{Slot => true}
            end,
            I1 = I0#{public_keys => PK1, upns => UPN1, valid_certs => Valid1},
            get_card_cert_info(Piv, Rest, I1);
        _Err ->
            get_card_cert_info(Piv, Rest, I0)
    end.

fetch_dp_and_crls(Cert) ->
    DPs = public_key:pkix_dist_points(Cert),
    fetch_dps(DPs).

fetch_dps([DP = #'DistributionPoint'{distributionPoint = {fullName, Names}} | Rest]) ->
    fetch_dp_names(DP, Names) ++ fetch_dps(Rest);
fetch_dps([_ | Rest]) ->
    fetch_dps(Rest);
fetch_dps([]) -> [].

fetch_dp_names(DP, [{uniformResourceIdentifier, "http"++_ = URL} | Rest]) ->
    case httpc:request(get, {URL, [{"connection", "close"}]},
                       [{timeout, 1000}], [{body_format, binary}]) of
        {ok, {_Status, _Headers, Body}} ->
            case (catch public_key:der_decode('CertificateList', Body)) of
                {'EXIT', _} ->
                    case (catch public_key:pem_decode(Body)) of
                        {'EXIT', _} -> fetch_dp_names(DP, Rest);
                        [] -> fetch_dp_names(DP, Rest);
                        CLs ->
                            [{DP, {D, public_key:der_decode('CertificateList', D)},
                                  {D, public_key:der_decode('CertificateList', D)}}
                             || {'CertificateList', D, not_encrypted} <- CLs]
                            ++ fetch_dp_names(DP, Rest)
                    end;
                CL = #'CertificateList'{} ->
                    [{DP, {Body, CL}, {Body, CL}} | fetch_dp_names(DP, Rest)]
            end;
        _ ->
            fetch_dp_names(DP, Rest)
    end;
fetch_dp_names(DP, [_ | Rest]) ->
    fetch_dp_names(DP, Rest);
fetch_dp_names(_DP, []) -> [].

find_ca([], Cert = #'OTPCertificate'{tbsCertificate = TBS}) ->
    #'OTPTBSCertificate'{issuer = {rdnSequence, Issuer}} = TBS,
    error({unknown_ca, Issuer});
find_ca([], _Cert) ->
    error(unknown_ca);
find_ca([CA | Rest], Cert) ->
    case public_key:pkix_is_issuer(Cert, CA) of
        true -> CA;
        false -> find_ca(Rest, Cert)
    end.

check_cert(Cert) ->
    DPandCRLs = fetch_dp_and_crls(Cert),
    CACertPath = application:get_env(rdpivy, ca_certs, "/etc/ssl/cert.pem"),
    {ok, CAData} = file:read_file(CACertPath),
    Entries0 = public_key:pem_decode(CAData),
    Entries1 = lists:foldl(fun
        ({'Certificate',E,_}, Acc) ->
            case (catch public_key:pkix_decode_cert(E, otp)) of
                {'EXIT', _} -> Acc;
                C = #'OTPCertificate'{} -> [C | Acc]
            end;
        (_, Acc) -> Acc
    end, [], Entries0),
    CA = find_ca(Entries1, Cert),
    Opts = [],
    {ok, _} = public_key:pkix_path_validation(CA, [Cert], Opts),
    CRLOpts = [
        {issuer_fun, {fun (_DP, CL, _Name, none) ->
            {ok, find_ca(Entries1, CL), []}
        end, none}}
    ],
    valid = public_key:pkix_crls_validate(Cert, DPandCRLs, CRLOpts).

challenge_slot(Piv, Slot, PubKey) ->
    Algo = nist_piv:algo_for_key(PubKey),
    Challenge = <<"rdpivy cak challenge", 0,
        (crypto:strong_rand_bytes(16))/binary>>,
    Hash = crypto:hash(sha256, Challenge),
    {ok, [{ok, CardSig}]} = apdu_transform:command(Piv, {sign, Slot,
        Algo, Hash}),
    true = public_key:verify(Challenge, sha256, CardSig, PubKey).
