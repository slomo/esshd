-module(esshd_parser).

-export([decode/2,decode/1]).

-include("./esshd.hrl").

decode([Packet,_Greeting]) ->
    decode(Packet,#pstate{}).

decode(#bpacket{payload=Payload},_State) ->
    <<Type:8,Rest/binary>> = Payload,
    case Type of
        ?SSH_MSG_KEXINIT ->
            decode_keyinit(Payload)
    end;
decode(Packet,ParserState) ->
    io:write(called),
    case ParserState#pstate.recvBits of
        empty ->
            <<PLength:32,PaddingLength:8,Rest/binary>> = Packet,
            MacLength=0,
            PayloadLength = PLength - PaddingLength - 1,
            {Payload,RandMac} = split_binary(Rest,PayloadLength),
            {Random,Mac} = split_binary(RandMac,PaddingLength + MacLength),
            BPacket = #bpacket{payload=Payload,mac=Mac},
            %io:write(BPacket),
            decode(BPacket,ParserState);
        _ ->
            % TODO: handle this
            io:write(nonEmptyPState)
    end.


decode_keyinit(<<?SSH_MSG_KEXINIT,Cookie:128,Rest/binary>>) ->
    {Lists,<<FollowKeyEx:8,0:32>>} = decode_lists(10,[],Rest),
    ListsStr = lists:map(
        fun (Bin) ->
                Str = binary_to_list(Bin),
                io:fwrite("~n >>> ~s ~n",[Str]),
                Str
        end,Lists),
    #packet{type=?SSH_MSG_KEXINIT,content=ListsStr++[FollowKeyEx]}.

decode_lists(0,Acc,SomeShit) ->
    {lists:reverse(Acc),SomeShit};
decode_lists(Num,Acc,<<Len:32,Data/binary>>) ->
    {List,Rest} = split_binary(Data,Len),
    decode_lists(Num-1,[List|Acc],Rest).
