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

-module(rdpivy_ui_fsm).
-behaviour(gen_statem).

-compile([{parse_transform, lager_transform}]).

-include_lib("ebox/include/ebox.hrl").

-export([
    start_link/3
    ]).

-export([
    init/1,
    callback_mode/0,
    terminate/3,
    code_change/4,
    loading/3,
    login/3,
    check_pin/3,
    get_chal/3,
    decrypt/3,
    confirm/3,
    decrypt_key/3,
    response/3
    ]).

-spec start_link(rdp_server:server(), lv:instance(), lv:point()) ->
    {ok, pid()} | {error, term()}.
start_link(Srv, Inst, Res) ->
    gen_statem:start_link(?MODULE, [Srv, Inst, Res], []).

-record(?MODULE, {
    srv :: rdp_server:server(),
    res :: lv:point(),
    inst :: lv:instance(),
    sty :: #{atom() => lv:style()},
    scard :: undefined | rdpdr_scard:state(),
    screen :: undefined | lv:scr(),
    pinchars :: lv:buffer(),
    events = [] :: [lv:event()],
    pin :: undefined | binary(),
    piv :: undefined | pid(),
    pin_rem :: undefined | {binary(), integer()},
    cinfo :: undefined | map(),
    slot :: undefined | nist_piv:slot(),
    chalbox :: undefined | ebox:box(),
    chal :: undefined | #ebox_challenge{},
    respbox :: undefined | ebox:box(),
    after_check = decrypt :: atom()
    }).

%% @private
init([Srv, Inst, {W, H}]) ->
    Sty = make_styles(Inst, {W, H}),
    {ok, Chars} = lv:make_buffer(Inst, "0123456789"),
    S0 = #?MODULE{srv = Srv, inst = Inst, res = {W, H}, sty = Sty,
                  pinchars = Chars},
    process_flag(trap_exit, true),
    {ok, loading, S0}.

make_styles(Inst, {W, H}) ->
    {ok, Scr} = lv_style:create(Inst),
    ok = lv_style:set_flex_flow(Scr, if (W > H) -> row; true -> column end),
    ok = lv_style:set_flex_align(Scr, center, center, center),
    ok = lv_style:set_bg_color(Scr, lv_color:make(16#48206c)),

    {ok, Flex} = lv_style:create(Inst),
    ok = lv_style:set_flex_flow(Flex, column),
    ok = lv_style:set_flex_align(Flex, center, start, if (W > H) -> start; true -> center end),
    ok = lv_style:set_bg_opa(Flex, 0),
    ok = lv_style:set_border_opa(Flex, 0),

    {ok, Row} = lv_style:create(Inst),
    ok = lv_style:set_flex_flow(Row, row),
    ok = lv_style:set_flex_align(Row, start, center, center),
    ok = lv_style:set_bg_opa(Row, 0),
    ok = lv_style:set_border_opa(Row, 0),
    ok = lv_style:set_pad_top(Row, 0),
    ok = lv_style:set_pad_bottom(Row, 0),
    ok = lv_style:set_pad_left(Row, 0),
    ok = lv_style:set_pad_right(Row, 0),
    ok = lv_style:set_width(Row, {percent, 100}),
    ok = lv_style:set_height(Row, content),

    {ok, Group} = lv_style:create(Inst),
    ok = lv_style:set_bg_opa(Group, 0.7),
    ok = lv_style:set_border_opa(Group, 0),
    ok = lv_style:set_width(Group, {percent, 100}),
    ok = lv_style:set_height(Group, content),

    {ok, Divider} = lv_style:create(Inst),
    ok = lv_style:set_border_side(Divider, [left]),
    ok = lv_style:set_border_color(Divider, lv_color:palette(black)),
    ok = lv_style:set_border_opa(Divider, 0.5),
    ok = lv_style:set_pad_left(Divider, 10),
    ok = lv_style:set_pad_top(Divider, 0),
    ok = lv_style:set_pad_bottom(Divider, 0),
    ok = lv_style:set_radius(Divider, 0),

    #{screen => Scr, flex => Flex, group => Group, group_divider => Divider,
      row => Row}.

make_screen(#?MODULE{inst = Inst, sty = Sty, res = {W, H}}) ->
    #{screen := ScreenStyle, flex := FlexStyle} = Sty,

    {ok, Screen} = lv_scr:create(Inst),
    ok = lv_obj:add_style(Screen, ScreenStyle),

    {ok, Flex} = lv_obj:create(Inst, Screen),
    ok = lv_obj:add_style(Flex, FlexStyle),

    if
        (W > H) ->
            FlexW = if (W div 3 < 500) -> 500; true -> W div 3 end,
            ok = lv_obj:set_size(Flex, {FlexW, {percent, 90}});
        true ->
            ok = lv_obj:set_size(Flex, {{percent, 80}, {percent, 66}})
    end,

    {Screen, Flex}.

make_waiting_screen(Text, S0 = #?MODULE{inst = Inst, sty = Sty}) ->
    #{screen := ScreenStyle} = Sty,
    {ok, Screen} = lv_scr:create(Inst),
    ok = lv_obj:add_style(Screen, ScreenStyle),
    {ok, Spinner} = lv_spinner:create(Screen, 1000, 90),
    ok = lv_obj:set_size(Spinner, {100, 100}),
    ok = lv_scr:load_anim(Inst, Screen, fade_in, 100, 0, true),
    {ok, Lbl} = lv_label:create(Screen),
    ok = lv_label:set_text(Lbl, Text),
    ok = lv_obj:set_style_text_color(Lbl, lv_color:palette(white)),
    Screen.

make_group(TopLevel, Symbol, #?MODULE{inst = Inst, sty = Sty}) ->
    #{flex := FlexStyle, group := GroupStyle, group_divider := DivStyle} = Sty,

    {ok, Outer} = lv_obj:create(Inst, TopLevel),
    ok = lv_obj:add_style(Outer, GroupStyle),

    {ok, Sym} = lv_img:create(Outer),
    ok = lv_img:set_src(Sym, Symbol),
    ok = lv_obj:align(Sym, left_mid),

    {ok, InnerFlex} = lv_obj:create(Inst, Outer),
    ok = lv_obj:add_style(InnerFlex, FlexStyle),
    ok = lv_obj:add_style(InnerFlex, DivStyle),
    ok = lv_obj:set_size(InnerFlex, {content, content}),
    ok = lv_obj:align(InnerFlex, top_left, {30, 0}),

    InnerFlex.

make_err_lbl(Parent, Fmt, Args) ->
    {ok, Lbl} = lv_label:create(Parent),
    Msg = io_lib:format(Fmt, Args),
    MsgLen = iolist_size(Msg),
    MsgTrunc = if MsgLen > 512 ->
        binary:part(iolist_to_binary(Msg), {0, 512});
        true -> Msg
    end,
    ok = lv_label:set_text(Lbl, MsgTrunc),
    ok = lv_obj:set_style_text_color(Lbl, lv_color:darken(red, 2)),
    ok = lv_obj:center(Lbl).
make_err_lbl(Parent, Fmt) ->
    make_err_lbl(Parent, Fmt, []).

err_dialog(#?MODULE{inst = Inst}, Fmt, Args) ->
    Msg = io_lib:format(Fmt, Args),
    MsgLen = iolist_size(Msg),
    MsgTrunc = if MsgLen > 512 ->
        binary:part(iolist_to_binary(Msg), {0, 512});
        true -> Msg
    end,
    {ok, Top} = lv_disp:get_layer_top(Inst),
    {ok, MsgBox} = lv_msgbox:create(Top, "Error", MsgTrunc, ["Close",
        "Exit"], false),
    ok = lv_obj:set_size(MsgBox, {{percent, 20}, content}),
    ok = lv_obj:center(MsgBox),
    {ok, Event, Ref} = lv_event:setup(MsgBox, value_changed, err_dialog_done),
    receive
        {Ref, err_dialog_done} ->
            {ok, Idx} = lv_msgbox:get_active_btn(MsgBox),
            case Idx of
                0 ->
                    ok = lv_msgbox:close(MsgBox),
                    ok;
                1 ->
                    disconnect
            end
    end.
err_dialog(Inst, Fmt) -> err_dialog(Inst, Fmt, []).

%% @private
callback_mode() -> [state_functions, state_enter].

%% @private
terminate(_Why, _State, #?MODULE{}) ->
    ok.

%% @private
code_change(_OldVsn, OldState, S0, _Extra) ->
    {ok, OldState, S0}.

%% @private
loading(enter, _PrevState, S0 = #?MODULE{}) ->
    Screen = make_waiting_screen("Looking for smartcard devices...", S0),
    {keep_state, S0#?MODULE{screen = Screen}, [{state_timeout, 500, check}]};
loading(state_timeout, check, S0 = #?MODULE{srv = Srv}) ->
    case rdpivy_scard:open(Srv) of
        {ok, SC0} ->
            {next_state, get_chal, S0#?MODULE{scard = SC0}};
        _Err ->
            {keep_state_and_data, [{state_timeout, 1000, check}]}
    end.

%% @private
login(enter, _PrevState, S0 = #?MODULE{inst = Inst, scard = SC0, sty = Sty}) ->
    WaitScreen = make_waiting_screen("Looking for smartcard devices...", S0),

    #{row := RowStyle} = Sty,
    {Screen, Flex} = make_screen(S0),
    {ok, InpGroup} = lv_group:create(Inst),

    {ok, HdrLabel} = lv_label:create(Flex),
    ok = lv_label:set_text(HdrLabel, "Select device"),
    ok = lv_obj:set_style_text_font(HdrLabel, {"montserrat", regular, 22}),
    ok = lv_obj:set_style_text_color(HdrLabel, lv_color:palette(white)),

    S1 = case rdpivy_scard:list_cards(SC0) of
        {ok, [], SC1} ->
            make_err_lbl(Screen, "No smartcard devices found"),
            S0#?MODULE{scard = SC1};
        {ok, Cards, SC1} ->
            #?MODULE{chalbox = #ebox_box{unlock_key = UnlockKey}} = S0,
            Evts = lists:foldl(fun (CardInfo, Acc) ->
                #{reader := RdrName, guid := Guid} = CardInfo,

                UPNMap = maps:get(upns, CardInfo, #{}),
                UPNs = lists:flatten(maps:values(UPNMap)),

                Group = make_group(Flex, sd_card, S0),

                {ok, RdrLbl} = lv_label:create(Group),
                ok = lv_label:set_text(RdrLbl, RdrName),
                ok = lv_obj:set_style_text_font(RdrLbl,
                    {"montserrat", regular, 20}),

                <<GuidN:128/big>> = Guid,
                GuidText = io_lib:format("GUID = ~.16B", [GuidN]),
                {ok, GuidLbl} = lv_label:create(Group),
                ok = lv_label:set_text(GuidLbl, GuidText),
                ok = lv_obj:set_style_text_font(GuidLbl,
                    {"source code pro", regular, 10}),
                ok = lv_obj:set_style_text_opa(GuidLbl, 0.8),

                case UPNs of
                    [UPN | _] ->
                        {ok, UpnLbl} = lv_label:create(Group),
                        ok = lv_label:set_text(UpnLbl, ["\xEF\x81\x94 ", UPN]);
                    _ ->
                        ok
                end,

                case CardInfo of
                    #{yk_version := {Maj,Min,Pat}, yk_serial := Serial} ->
                        {ok, YkLbl} = lv_label:create(Group),
                        Text = io_lib:format("\xEF\x8a\x87 YubiKey #~B, firmware v~B.~B.~B",
                            [Serial, Maj, Min, Pat]),
                        ok = lv_label:set_text(YkLbl, Text);
                    _ ->
                        ok
                end,

                PubKeys = maps:values(maps:get(public_keys, CardInfo, #{})),
                Match = lists:any(fun (PubKey) ->
                    case PubKey of
                        UnlockKey -> true;
                        _ -> false
                    end
                end, PubKeys),

                case Match of
                    true ->
                        {ok, PinText} = lv_textarea:create(Group),
                        ok = lv_textarea:set_one_line(PinText, true),
                        ok = lv_textarea:set_text_selection(PinText, true),
                        #?MODULE{pinchars = Chars} = S0,
                        ok = lv_textarea:set_placeholder_text(PinText, "PIN"),
                        ok = lv_textarea:set_accepted_chars(PinText, Chars),
                        ok = lv_textarea:set_password_mode(PinText, true),
                        ok = lv_group:add_obj(InpGroup, PinText),

                        CAKValid = maps:get(piv_card_auth,
                            maps:get(valid_certs, CardInfo, #{}), false),
                        case CAKValid of
                            true ->
                                ok;
                            false ->
                                make_err_lbl(Group,
                                    "\xEF\x81\xB1 Warning: could not verify CAK!\n"
                                    "  Device is unsigned or may be fake!")
                        end,

                        case S0 of
                            #?MODULE{pin_rem = {RdrName, Rem}} ->
                                make_err_lbl(Group,
                                    "\xEF\x81\xB1 Incorrect PIN. ~B attempts remaining.",
                                    [Rem]),
                                ok = lv_group:focus_obj(PinText);
                            _ ->
                                ok
                        end,

                        {ok, YkBtn} = lv_btn:create(Group),
                        {ok, YkBtnLbl} = lv_label:create(YkBtn),
                        ok = lv_label:set_text(YkBtnLbl, "Login"),

                        {ok, YkBtnEvent, _} = lv_event:setup(YkBtn, short_clicked,
                            {login, CardInfo, PinText}),
                        {ok, YkAcEvent, _} = lv_event:setup(PinText, ready,
                            {login, CardInfo, PinText}),

                        [YkBtnEvent, YkAcEvent | Acc];
                    false ->
                        make_err_lbl(Group, "No matching keys found."),
                        Acc
                end
            end, [], Cards),
            S0#?MODULE{scard = SC1, events = Evts};
        Err ->
            make_err_lbl(Screen, "Failed to list cards: ~p", [Err]),
            S0
    end,

    ok = lv_scr:load_anim(Inst, Screen, fade_in, 500, 0, true),

    ok = lv_indev:set_group(Inst, keyboard, InpGroup),

    {keep_state, S1#?MODULE{screen = Screen}};

login(info, {_, {login, CardInfo, PinText}}, S0 = #?MODULE{scard = SC0}) ->
    {ok, PIN} = lv_textarea:get_text(PinText),
    #{reader := Rdr} = CardInfo,
    Screen = make_waiting_screen("Connecting...", S0),
    {ok, Piv, SC1} = rdpivy_scard:connect(Rdr, SC0),
    {next_state, check_pin, S0#?MODULE{piv = Piv, scard = SC1, pin = PIN,
        screen = Screen, cinfo = CardInfo}}.

begin_txn(S0 = #?MODULE{piv = Piv, scard = SC0, cinfo = CI}) ->
    case apdu_transform:begin_transaction(Piv) of
        ok ->
            {ok, Piv, S0};
        {error, {scard, 16#80100068}} ->
            #{reader := Rdr} = CI,
            {ok, SC1} = rdpdr_scard:disconnect(leave, SC0),
            exit(Piv, kill),
            receive {'EXIT', Piv, _} -> ok end,
            {ok, Piv2, SC2} = rdpivy_scard:connect(Rdr, SC1),
            S1 = S0#?MODULE{piv = Piv2, scard = SC2},
            {ok, Piv2, S1}
    end.

disconnect(S0 = #?MODULE{piv = Piv, scard = SC0}) ->
    {ok, SC1} = rdpdr_scard:disconnect(leave, SC0),
    exit(Piv, kill),
    receive {'EXIT', Piv, _} -> ok end,
    S0#?MODULE{piv = undefined, scard = SC1}.

%% @private
check_pin(enter, _PrevState, S0 = #?MODULE{}) ->
    Screen = make_waiting_screen("Checking PIN...", S0),
    {keep_state, S0#?MODULE{screen = Screen}, [{state_timeout, 0, check}]};
check_pin(state_timeout, check, S0 = #?MODULE{pin = PIN, cinfo = CI,
                                              after_check = St}) ->
    #{public_keys := PK} = CI,
    {ok, Piv, S1} = begin_txn(S0),
    {ok, [{ok, _}]} = apdu_transform:command(Piv, select),
    case PK of
        #{piv_card_auth := CAK} ->
            Alg = nist_piv:algo_for_key(CAK),
            Challenge = <<"rdpivy cak challenge", 0,
                (crypto:strong_rand_bytes(16))/binary>>,
            HashAlgo = case Alg of
                rsa2048 -> sha256;
                eccp256 -> sha256;
                eccp384 -> sha384;
                eccp521 -> sha512
            end,
            Hash = crypto:hash(HashAlgo, Challenge),
            {ok, [{ok, CardSig}]} = apdu_transform:command(Piv, {sign,
                piv_card_auth, Alg, Hash}),
            true = public_key:verify(Challenge, HashAlgo, CardSig, CAK);
        _ ->
            ok
    end,
    case apdu_transform:command(Piv, {verify_pin, piv_pin, PIN}) of
        {ok, [ok]} ->
            {next_state, St, S1};
        {ok, [{error, bad_auth, Attempts}]} ->
            #?MODULE{cinfo = #{reader := Rdr}} = S1,
            apdu_transform:end_transaction(Piv),
            S2 = disconnect(S1),
            {next_state, login, S2#?MODULE{pin_rem = {Rdr, Attempts},
                                           pin = undefined}};
        Err ->
            lager:debug("err = ~p", [Err]),
            apdu_transform:end_transaction(Piv),
            {stop, pin_failure, disconnect(S1)}
    end.

%% @private
decrypt(enter, _PrevState, S0 = #?MODULE{}) ->
    Screen = make_waiting_screen("Decrypting box...\nTouch may be required!", S0),
    {keep_state, S0#?MODULE{screen = Screen}, [{state_timeout, 0, decrypt}]};
decrypt(state_timeout, decrypt, S0 = #?MODULE{piv = Piv, cinfo = CI,
                                              chalbox = B0}) ->
    #{public_keys := PK} = CI,
    #ebox_box{unlock_key = UnlockKey} = B0,
    {value, {Slot, _}} = lists:search(fun
        ({_Slot, PubKey}) when (PubKey =:= UnlockKey) -> true;
        (_) -> false
    end, maps:to_list(PK)),
    S1 = S0#?MODULE{slot = Slot},
    Res = ebox:decrypt_box(B0, {ebox_key_piv, {Piv, Slot, UnlockKey}}),
    apdu_transform:end_transaction(Piv, reset),
    case Res of
        {ok, B1} ->
            Chal = ebox:decode_challenge(B1),
            S2 = S1#?MODULE{chal = Chal},
            {next_state, confirm, S2};
        Err ->
            S2 = disconnect(S1),
            lager:debug("decrypt box failed: ~p", [Err]),
            case err_dialog(S2, "Decryption failed:\n~p", [Err]) of
                ok ->
                    {next_state, get_chal, S2};
                disconnect ->
                    #?MODULE{srv = Srv} = S2,
                    rdp_server:close(Srv),
                    {stop, normal, S2}
            end
    end.

%% @private
confirm(enter, _PrevState, S0 = #?MODULE{inst = Inst, sty = Sty, chal = Chal,
                                         res = {W, _}}) ->
    #ebox_challenge{type = Type, description = Descr, hostname = Hostname,
                    created = CTime, words = Words} = Chal,

    {Screen, Flex} = make_screen(S0),

    #{group := GroupStyle, flex := FlexStyle, row := RowStyle} = Sty,
    {ok, Outer} = lv_obj:create(Inst, Flex),
    ok = lv_obj:add_style(Outer, FlexStyle),
    ok = lv_obj:add_style(Outer, GroupStyle),

    {ok, HdrLabel} = lv_label:create(Outer),
    ok = lv_label:set_text(HdrLabel, "Confirm"),
    ok = lv_obj:set_style_text_font(HdrLabel, {"montserrat", regular, 22}),

    {ok, Tbl} = lv_table:create(Outer),
    ok = lv_table:set_col_cnt(Tbl, 2),
    ok = lv_table:set_col_width(Tbl, 0, (W div 3 - 80) div 4),
    ok = lv_table:set_col_width(Tbl, 1, 3 * (W div 3 - 80) div 4),
    ok = lv_table:set_row_cnt(Tbl, 4),
    ok = lv_obj:set_size(Tbl, {{percent, 100}, content}),

    ok = lv_table:set_cell_value(Tbl, 0, 0, "Purpose"),
    TypeStr = case Type of
        recovery -> "Recovery of at-rest encryption keys";
        verify_audit -> "Verification of audit trail"
    end,
    ok = lv_table:set_cell_value(Tbl, 0, 1, TypeStr),

    ok = lv_table:set_cell_value(Tbl, 1, 0, "Description"),
    case Descr of
        undefined -> ok;
        _ ->         ok = lv_table:set_cell_value(Tbl, 1, 1, Descr)
    end,

    ok = lv_table:set_cell_value(Tbl, 2, 0, "Hostname"),
    case Hostname of
        undefined -> ok;
        _ ->         ok = lv_table:set_cell_value(Tbl, 2, 1, Hostname)
    end,

    ok = lv_table:set_cell_value(Tbl, 3, 0, "Created at"),
    case CTime of
        undefined -> ok;
        _ ->
            CTimeStr = calendar:system_time_to_rfc3339(CTime, [{unit, second}]),
            ok = lv_table:set_cell_value(Tbl, 3, 1, CTimeStr)
    end,

    {ok, WordsHdr} = lv_label:create(Outer),
    ok = lv_label:set_text(WordsHdr, "VERIFICATION WORDS:"),
    ok = lv_obj:set_style_text_font(WordsHdr, {"montserrat", regular, 18}),
    ok = lv_obj:set_style_text_color(WordsHdr, lv_color:darken(red, 4)),

    {ok, WordLbl} = lv_label:create(Outer),
    ok = lv_label:set_text(WordLbl, lists:join("  ", Words)),
    ok = lv_obj:set_style_text_font(WordLbl, {"montserrat", regular, 16}),
    ok = lv_obj:set_style_text_color(WordLbl, lv_color:darken(red, 4)),

    {ok, InsLabel} = lv_label:create(Outer),
    ok = lv_label:set_text(InsLabel, "Check the details above carefully.\n"
        "If they match the originator of the challenge, press Confirm."),
    ok = lv_obj:set_style_pad_top(InsLabel, 30),

    {ok, BtnRow} = lv_obj:create(Inst, Outer),
    ok = lv_obj:add_style(BtnRow, RowStyle),

    {ok, CBtn} = lv_btn:create(BtnRow),
    {ok, CBtnLbl} = lv_label:create(CBtn),
    ok = lv_label:set_text(CBtnLbl, "Confirm"),

    {ok, XBtn} = lv_btn:create(BtnRow),
    {ok, XBtnLbl} = lv_label:create(XBtn),
    ok = lv_label:set_text(XBtnLbl, "Cancel"),
    ok = lv_obj:set_style_bg_color(XBtn, lv_color:lighten(red, 2)),

    {ok, CBtnEvt, _} = lv_event:setup(CBtn, short_clicked, confirm),
    {ok, XBtnEvt, _} = lv_event:setup(XBtn, short_clicked, cancel),

    ok = lv_scr:load_anim(Inst, Screen, fade_in, 500, 0, true),

    {keep_state, S0#?MODULE{events = [CBtnEvt, XBtnEvt], screen = Screen}};

confirm(info, {'EXIT', Pid, _Why}, S0 = #?MODULE{piv = Pid}) ->
    {keep_state, S0#?MODULE{piv = undefined}};
confirm(info, {'EXIT', _Pid, _Why}, _S0 = #?MODULE{}) ->
    keep_state_and_data;

confirm(info, {_, cancel}, S0 = #?MODULE{srv = Srv}) ->
    rdp_server:close(Srv),
    {stop, normal, disconnect(S0)};

confirm(info, {_, confirm}, S0 = #?MODULE{}) ->
    {next_state, check_pin, S0#?MODULE{after_check = decrypt_key}}.

%% @private
decrypt_key(enter, _PrevState, S0 = #?MODULE{}) ->
    Screen = make_waiting_screen("Decrypting key piece...\nTouch may be required!", S0),
    {keep_state, S0#?MODULE{screen = Screen}, [{state_timeout, 0, decrypt}]};
decrypt_key(state_timeout, decrypt, S0 = #?MODULE{piv = Piv, cinfo = CI,
                                                  chal = Chal, slot = Slot}) ->
    #ebox_challenge{keybox = KB0} = Chal,
    #ebox_box{unlock_key = UnlockKey} = KB0,
    Res = ebox:decrypt_box(KB0, {ebox_key_piv, {Piv, Slot, UnlockKey}}),
    apdu_transform:end_transaction(Piv, reset),
    S1 = disconnect(S0),
    case Res of
        {ok, KB1} ->
            Resp = ebox:response_box(Chal, KB1),
            S2 = S1#?MODULE{respbox = Resp},
            {next_state, response, S2};
        Err ->
            lager:debug("decrypt key box failed: ~p", [Err]),
            case err_dialog(S1, "Decryption failed:\n~p", [Err]) of
                ok ->
                    {next_state, get_chal, S1};
                disconnect ->
                    #?MODULE{srv = Srv} = S0,
                    rdp_server:close(Srv),
                    {stop, normal, S1}
            end
    end.

wrap70(<<Line:60/binary, Rest/binary>>) ->
    [[Line, $\n] | wrap70(Rest)];
wrap70(Rest) -> [Rest, $\n].

%% @private
response(enter, _PrevState, S0 = #?MODULE{respbox = RB, sty = Sty, inst = Inst}) ->
    Data = ebox:encode(RB),
    Base64 = base64:encode(Data),
    Lines = wrap70(Base64),
    Resp = ["-- Begin response --\n", Lines, "-- End response --\n"],

    {Screen, Flex} = make_screen(S0),

    #{group := GroupStyle, flex := FlexStyle, row := RowStyle} = Sty,
    {ok, Outer} = lv_obj:create(Inst, Flex),
    ok = lv_obj:add_style(Outer, FlexStyle),
    ok = lv_obj:add_style(Outer, GroupStyle),

    {ok, HdrLabel} = lv_label:create(Outer),
    ok = lv_label:set_text(HdrLabel, "Response"),
    ok = lv_obj:set_style_text_font(HdrLabel, {"montserrat", regular, 22}),

    {ok, RespTxt} = lv_textarea:create(Outer),
    ok = lv_obj:set_size(RespTxt, {{percent, 100}, 500}),
    ok = lv_obj:set_style_text_font(RespTxt, {"source code pro", regular, 12}),
    ok = lv_textarea:set_text(RespTxt, Resp),

    {ok, BtnRow} = lv_obj:create(Inst, Outer),
    ok = lv_obj:add_style(BtnRow, RowStyle),

    {ok, CBtn} = lv_btn:create(BtnRow),
    {ok, CBtnLbl} = lv_label:create(CBtn),
    ok = lv_label:set_text(CBtnLbl, "Copy to clipboard"),

    {ok, XBtn} = lv_btn:create(BtnRow),
    {ok, XBtnLbl} = lv_label:create(XBtn),
    ok = lv_label:set_text(XBtnLbl, "Exit"),
    ok = lv_obj:set_style_bg_color(XBtn, lv_color:lighten(red, 2)),

    {ok, CBtnEvt, _} = lv_event:setup(CBtn, short_clicked, {copy, Resp, CBtn}),
    {ok, XBtnEvt, _} = lv_event:setup(XBtn, short_clicked, exit),

    ok = lv_scr:load_anim(Inst, Screen, fade_in, 500, 0, true),

    {keep_state, S0#?MODULE{events = [CBtnEvt, XBtnEvt], screen = Screen}};

response(info, {'EXIT', Pid, _Why}, S0 = #?MODULE{piv = Pid}) ->
    {keep_state, S0#?MODULE{piv = undefined}};
response(info, {'EXIT', _Pid, _Why}, _S0 = #?MODULE{}) ->
    keep_state_and_data;

response(info, {_, exit}, S0 = #?MODULE{srv = Srv}) ->
    rdp_server:close(Srv),
    {stop, normal, S0};

response(info, {_, {copy, Data, Btn}}, S0 = #?MODULE{srv = Srv}) ->
    {ok, Spinner} = lv_spinner:create(Btn, 90, 1000),
    ok = lv_obj:set_size(Spinner, {30, 30}),
    case rdp_server:get_vchan_pid(Srv, cliprdr_fsm) of
        {ok, ClipRdr} ->
            Formats = #{
                text => Data,
                unicode => unicode:characters_to_binary(Data, utf8, {utf16,little})
            },
            case cliprdr_fsm:copy(ClipRdr, Formats) of
                ok ->
                    ok = lv_obj:add_state(Btn, checked),
                    lv_obj:del(Spinner),
                    keep_state_and_data;
                Err ->
                    case err_dialog(S0, "Copy failed:\n~p", [Err]) of
                        ok ->
                            keep_state_and_data;
                        disconnect ->
                            rdp_server:close(Srv),
                            {stop, normal, S0}
                    end
            end;
        _ ->
            case err_dialog(S0, "Clipboard redirection not enabled") of
                ok ->
                    keep_state_and_data;
                disconnect ->
                    rdp_server:close(Srv),
                    {stop, normal, S0}
            end
    end.

%% @private
get_chal(enter, _PrevState, S0 = #?MODULE{inst = Inst, sty = Sty}) ->
    {Screen, Flex} = make_screen(S0),
    {ok, InpGroup} = lv_group:create(Inst),

    #{group := GroupStyle, flex := FlexStyle, row := RowStyle} = Sty,
    {ok, Outer} = lv_obj:create(Inst, Flex),
    ok = lv_obj:add_style(Outer, FlexStyle),
    ok = lv_obj:add_style(Outer, GroupStyle),

    {ok, HdrLabel} = lv_label:create(Outer),
    ok = lv_label:set_text(HdrLabel, "pivy-box challenge-response"),
    ok = lv_obj:set_style_text_font(HdrLabel, {"montserrat", regular, 22}),

    {ok, ChalInp} = lv_textarea:create(Outer),
    ok = lv_textarea:set_text_selection(ChalInp, true),
    ok = lv_textarea:set_placeholder_text(ChalInp, "Paste challenge here"),
    ok = lv_obj:set_style_text_font(ChalInp, {"source code pro", regular, 12}),
    ok = lv_obj:set_size(ChalInp, {{percent, 100}, 500}),
    ok = lv_group:add_obj(InpGroup, ChalInp),

    {ok, BtnRow} = lv_obj:create(Inst, Outer),
    ok = lv_obj:add_style(BtnRow, RowStyle),

    {ok, Btn} = lv_btn:create(BtnRow),
    {ok, BtnLbl} = lv_label:create(Btn),
    ok = lv_label:set_text(BtnLbl, "Submit"),

    {ok, PBtn} = lv_btn:create(BtnRow),
    {ok, PBtnLbl} = lv_label:create(PBtn),
    ok = lv_label:set_text(PBtnLbl, "Paste clipboard"),

    {ok, BtnEvent, _} = lv_event:setup(Btn, short_clicked,
        {submit, ChalInp}),
    {ok, AcEvent, _} = lv_event:setup(ChalInp, ready,
        {submit, ChalInp}),
    {ok, PstEvent, _} = lv_event:setup(PBtn, short_clicked,
        {paste_into, ChalInp}),

    ok = lv_scr:load_anim(Inst, Screen, fade_in, 500, 0, true),
    ok = lv_indev:set_group(Inst, keyboard, InpGroup),
    {keep_state, S0#?MODULE{screen = Screen, events = [BtnEvent, AcEvent,
        PstEvent]}};

get_chal(info, {_, {paste_into, Inp}}, S0 = #?MODULE{srv = Srv}) ->
    case rdp_server:get_vchan_pid(Srv, cliprdr_fsm) of
        {ok, ClipRdr} ->
            case cliprdr_fsm:list_formats(ClipRdr) of
                {ok, Fmts} ->
                    Fmt = case lists:member(unicode, Fmts) of
                        true -> unicode;
                        false -> text
                    end,
                    case cliprdr_fsm:paste(ClipRdr, Fmt) of
                        {ok, Data} ->
                            ok = lv_textarea:set_text(Inp, Data),
                            keep_state_and_data;
                        Err ->
                            case err_dialog(S0, "Paste failed:\n~p", [Err]) of
                                ok ->
                                    keep_state_and_data;
                                disconnect ->
                                    rdp_server:close(Srv),
                                    {stop, normal, S0}
                            end
                    end;
                Err ->
                    case err_dialog(S0, "Paste failed:\n~p", [Err]) of
                        ok ->
                            keep_state_and_data;
                        disconnect ->
                            rdp_server:close(Srv),
                            {stop, normal, S0}
                    end
            end;
        _ ->
            case err_dialog(S0, "Clipboard redirection not enabled") of
                ok ->
                    keep_state_and_data;
                disconnect ->
                    rdp_server:close(Srv),
                    {stop, normal, S0}
            end
    end;

get_chal(info, {_, {submit, ChalInp}}, S0 = #?MODULE{inst = Inst}) ->
    {ok, Data} = lv_textarea:get_text(ChalInp),
    Lines0 = binary:split(Data, [<<"\r\n">>, <<"\n">>], [global]),
    Lines1 = lists:filter(fun
        (<<"--", _/binary>>) -> false;
        (_) -> true
    end, Lines0),
    Lines2 = lists:map(fun (Line) ->
        re:replace(Line, "[^-A-Za-z0-9+/=]", "", [global])
    end, Lines1),
    Base64 = iolist_to_binary(Lines2),
    case (catch base64:decode(Base64)) of
        {'EXIT', Why} ->
            #?MODULE{srv = Srv} = S0,
            case err_dialog(S0, "Base64 decoding failed:\n~p", [Why]) of
                ok ->
                    keep_state_and_data;
                disconnect ->
                    #?MODULE{srv = Srv} = S0,
                    rdp_server:close(Srv),
                    {stop, normal, S0}
            end;
        DataBin ->
            case (catch ebox:decode(DataBin)) of
                {'EXIT', Why} ->
                    case err_dialog(S0, "Ebox decoding failed:\n~p", [Why]) of
                        ok ->
                            keep_state_and_data;
                        disconnect ->
                            #?MODULE{srv = Srv} = S0,
                            rdp_server:close(Srv),
                            {stop, normal, S0}
                    end;
                B0 = #ebox_box{} ->
                    S1 = S0#?MODULE{chalbox = B0},
                    {next_state, login, S1}
            end
    end.
