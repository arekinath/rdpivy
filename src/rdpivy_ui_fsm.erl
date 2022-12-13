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
    get_chal/3
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
    cinfo :: undefined | map()
    }).

%% @private
init([Srv, Inst, {W, H}]) ->
    Sty = make_styles(Inst, {W, H}),
    {ok, Chars} = lv:make_buffer(Inst, "0123456789"),
    S0 = #?MODULE{srv = Srv, inst = Inst, res = {W, H}, sty = Sty,
                  pinchars = Chars},
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

    {ok, Group} = lv_style:create(Inst),
    ok = lv_style:set_bg_opa(Group, 0.7),
    ok = lv_style:set_border_opa(Group, 0),

    {ok, Divider} = lv_style:create(Inst),
    ok = lv_style:set_border_side(Divider, [left]),
    ok = lv_style:set_border_color(Divider, lv_color:palette(black)),
    ok = lv_style:set_border_opa(Divider, 0.5),
    ok = lv_style:set_pad_left(Divider, 10),
    ok = lv_style:set_pad_top(Divider, 0),
    ok = lv_style:set_pad_bottom(Divider, 0),
    ok = lv_style:set_radius(Divider, 0),

    #{screen => Scr, flex => Flex, group => Group, group_divider => Divider}.

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
    ok = lv_obj:set_size(Outer, {{percent, 100}, content}),

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
    ok = lv_obj:set_style_text_color(Lbl, lv_color:make(16#FF6060)),
    ok = lv_obj:center(Lbl).
make_err_lbl(Parent, Fmt) ->
    make_err_lbl(Parent, Fmt, []).

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
            {next_state, login, S0#?MODULE{scard = SC0}};
        _Err ->
            {keep_state_and_data, [{state_timeout, 1000, check}]}
    end.

%% @private
login(enter, _PrevState, S0 = #?MODULE{inst = Inst, scard = SC0}) ->
    {Screen, Flex} = make_screen(S0),
    {ok, InpGroup} = lv_group:create(Inst),

    S1 = case rdpivy_scard:list_cards(SC0) of
        {ok, [], SC1} ->
            make_err_lbl(Screen, "No smartcard devices found"),
            S0#?MODULE{scard = SC1};
        {ok, Cards, SC1} ->
            Evts = lists:foldl(fun (CardInfo, Acc) ->
                #{reader := RdrName, guid := Guid, upns := UPNs} = CardInfo,

                Group = make_group(Flex, sd_card, S0),

                {ok, RdrLbl} = lv_label:create(Group),
                ok = lv_label:set_text(RdrLbl, RdrName),
                ok = lv_obj:set_style_text_font(RdrLbl,
                    {"montserrat", regular, 20}),

                <<GuidN:128/big>> = Guid,
                GuidText = io_lib:format("~.16B", [GuidN]),
                {ok, GuidLbl} = lv_label:create(Group),
                ok = lv_label:set_text(GuidLbl, GuidText),
                ok = lv_obj:set_style_text_font(GuidLbl,
                    {"montserrat", regular, 10}),
                ok = lv_obj:set_style_text_opa(GuidLbl, 0.8),

                case UPNs of
                    [UPN | _] ->
                        {ok, UpnLbl} = lv_label:create(Group),
                        ok = lv_label:set_text(UpnLbl, UPN);
                    _ ->
                        ok
                end,

                case CardInfo of
                    #{yk_version := {Maj,Min,Pat}, yk_serial := Serial} ->
                        {ok, YkLbl} = lv_label:create(Group),
                        Text = io_lib:format("YubiKey #~B, firmware v~B.~B.~B",
                            [Serial, Maj, Min, Pat]),
                        ok = lv_label:set_text(YkLbl, Text);
                    _ ->
                        ok
                end,

                {ok, PinText} = lv_textarea:create(Group),
                ok = lv_textarea:set_one_line(PinText, true),
                ok = lv_textarea:set_text_selection(PinText, true),
                #?MODULE{pinchars = Chars} = S0,
                ok = lv_textarea:set_placeholder_text(PinText, "PIN"),
                ok = lv_textarea:set_accepted_chars(PinText, Chars),
                ok = lv_textarea:set_password_mode(PinText, true),
                ok = lv_group:add_obj(InpGroup, PinText),

                case S0 of
                    #?MODULE{pin_rem = {RdrName, Rem}} ->
                        {ok, ErrLbl} = lv_label:create(Group),
                        ErrText = io_lib:format(
                            "Incorrect PIN. ~B attempts remaining.",
                            [Rem]),
                        ok = lv_label:set_text(ErrLbl, ErrText),
                        ok = lv_obj:set_style_text_color(ErrLbl,
                            lv_color:darken(red, 2)),
                        ok = lv_group:focus_obj(PinText);
                    _ ->
                        ok
                end,

                {ok, YkBtn} = lv_btn:create(Group),
                {ok, YkBtnLbl} = lv_label:create(YkBtn),
                ok = lv_label:set_text(YkBtnLbl, "Login"),

                {ok, YkBtnEvent, _} = lv_event:setup(YkBtn, pressed,
                    {login, CardInfo, PinText}),
                {ok, YkAcEvent, _} = lv_event:setup(PinText, ready,
                    {login, CardInfo, PinText}),

                [YkBtnEvent, YkAcEvent | Acc]
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


%% @private
check_pin(enter, _PrevState, S0 = #?MODULE{}) ->
    Screen = make_waiting_screen("Checking PIN...", S0),
    {keep_state, S0#?MODULE{screen = Screen}, [{state_timeout, 0, check}]};
check_pin(state_timeout, check, S0 = #?MODULE{piv = Piv, pin = PIN,
                                              scard = SC0}) ->
    ok = apdu_transform:begin_transaction(Piv),
    {ok, [{ok, #{version := V}}]} = apdu_transform:command(Piv, select),
    case apdu_transform:command(Piv, {verify_pin, piv_pin, PIN}) of
        {ok, [ok]} ->
            apdu_transform:end_transaction(Piv),
            {next_state, get_chal, S0};
        {ok, [{error, bad_auth, Attempts}]} ->
            #?MODULE{cinfo = #{reader := Rdr}} = S0,
            apdu_transform:end_transaction(Piv),
            {ok, SC1} = rdpdr_scard:disconnect(leave, SC0),
            {next_state, login, S0#?MODULE{pin_rem = {Rdr, Attempts},
                                           piv = undefined, pin = undefined,
                                           scard = SC1}}
    end.

%% @private
get_chal(enter, _PrevState, S0 = #?MODULE{inst = Inst, sty = Sty}) ->
    {Screen, Flex} = make_screen(S0),
    {ok, InpGroup} = lv_group:create(Inst),

    #{group := GroupStyle, flex := FlexStyle} = Sty,
    {ok, Outer} = lv_obj:create(Inst, Flex),
    ok = lv_obj:add_style(Outer, FlexStyle),
    ok = lv_obj:add_style(Outer, GroupStyle),
    ok = lv_obj:set_size(Outer, {{percent, 100}, content}),

    {ok, HdrLabel} = lv_label:create(Outer),
    ok = lv_label:set_text(HdrLabel, "Challenge/response"),
    ok = lv_obj:set_style_text_font(HdrLabel, {"montserrat", regular, 22}),

    {ok, ChalInp} = lv_textarea:create(Outer),
    ok = lv_textarea:set_text_selection(ChalInp, true),
    ok = lv_textarea:set_placeholder_text(ChalInp, "Paste challenge here"),
    ok = lv_obj:set_size(ChalInp, {{percent, 100}, 500}),
    ok = lv_group:add_obj(InpGroup, ChalInp),

    {ok, Btn} = lv_btn:create(Outer),
    {ok, BtnLbl} = lv_label:create(Btn),
    ok = lv_label:set_text(BtnLbl, "Submit"),

    {ok, BtnEvent, _} = lv_event:setup(Btn, pressed,
        {submit, ChalInp}),
    {ok, AcEvent, _} = lv_event:setup(ChalInp, ready,
        {submit, ChalInp}),

    ok = lv_scr:load_anim(Inst, Screen, fade_in, 500, 0, true),
    ok = lv_indev:set_group(Inst, keyboard, InpGroup),
    {keep_state, S0#?MODULE{screen = Flex, events = [BtnEvent, AcEvent]}};

get_chal(info, {_, {submit, ChalInp}}, S0 = #?MODULE{inst = Inst, screen = Scr}) ->
    {ok, Data} = lv_textarea:get_text(ChalInp),
    Lines0 = binary:split(Data, [<<"\r\n">>, <<"\n">>], [global]),
    lager:debug("lines = ~p", [Lines0]),
    Lines1 = lists:filter(fun
        (<<"--", _/binary>>) -> false;
        (_) -> true
    end, Lines0),
    Lines2 = lists:map(fun (Line) ->
        re:replace(Line, "[^-A-Za-z0-9+/=]", "", [global])
    end, Lines1),
    Base64 = iolist_to_binary(Lines2),
    lager:debug("base64 = ~s", [Base64]),
    case (catch base64:decode(Base64)) of
        {'EXIT', Why} ->
            make_err_lbl(Scr, "Base64 error: ~p", [Why]),
            keep_state_and_data;
        DataBin ->
            case (catch ebox:decode(DataBin)) of
                {'EXIT', Why} ->
                    make_err_lbl(Scr, "Ebox decode error: ~p", [Why]),
                    keep_state_and_data;
                B0 = #ebox_box{unlock_key = {Point, Curve}} ->
                    make_err_lbl(Scr, "decode ok"),
                    keep_state_and_data
            end
    end.
