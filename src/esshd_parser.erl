-module(esshd_parser).

-export([decode_packet/2,decode_greeter/1]).
-compile(export_all).

-include("./esshd.hrl").



%------------------------------------------------------------------------------
%% all raw decode functions shall be called with the current avaible data
%% they also schould return with either {ok,<decoded>,<bytesoverhead>},
%% {wait,<datalengthmissing>} or {error,<reason>}


% FIXME: im am ugly and consume infinitamounts of memory
decode_greeter(Data) ->
    {ok,MP} = re:compile("SSH-2.0-[^ \r\n-]+( [^\r\n]+)?\r\n([.\s])*"),
    case re:run(binary_to_list(Data),MP) of
        {match,[{0,Last}|_T]} ->
            {Greeting,Remaining} = split_binary(Data,Last),
            {ok,Greeting,Remaining};
        nomatch ->
            {wait,-1}
    end.


decode_packet(Data,MacLength) ->
    <<ExpectedLength:32,PaddingLength:8,ContentRest/binary>> = Data,
    ActualLength = bit_size(ContentRest),
    if
        ActualLength < ExpectedLength ->
            {wait,ExpectedLength-ActualLength};
        true ->
            PayloadLength =  - PaddingLength - 1,
            {Payload,PadMacRest} = split_binary(ContentRest,PayloadLength),
            {_Padding,MacRest} = split_binary(PadMacRest,PaddingLength),
            {Mac,Rest} = split_binary(MacRest,MacLength),
            BPacket = #bpacket{payload=Payload,mac=Mac},
            {ok,BPacket,Rest}
    end.

%------------------------------------------------------------------------------
%% all binary packet functions return either {ok,<result>} or {error,<reason>}

decode_payload_keyinit(<<?SSH_MSG_KEXINIT,_Cookie:128,Rest/binary>>) ->
    {ok,Lists,<<FollowKeyEx:8,0:32>>} = decode_lists(10,[],Rest),
    ListsStr = lists:map(
        fun (Bin) ->
                Str = binary_to_list(Bin),
                io:fwrite("~n >>> ~s ~n",[Str]),
                Str
        end,Lists),
    #packet{type=?SSH_MSG_KEXINIT,content=ListsStr++[FollowKeyEx]}.

%------------------------------------------------------------------------------
% helpers

unwarp_bpacket(#bpacket{payload=Payload},Handler) ->
    Handler(Payload).

decode_lists(0,Acc,SomeShit) ->
    {ok,lists:reverse(Acc),SomeShit};
decode_lists(Num,Acc,<<Len:32,Data/binary>>) ->
    {List,Rest} = split_binary(Data,Len),
    decode_lists(Num-1,[List|Acc],Rest).
