-module(esshd_srv).

-export([start/0]).


start() ->
    {ok, LSock} = gen_tcp:listen(4000, [binary, {packet, 0},{active, false}]),
    {ok, Sock} = gen_tcp:accept(LSock),
    gen_tcp:send(Sock,<<"SSH-2.0-OpenSSH_5.8p1 Debian-1ubuntu3\r\n">>),
    Go = do_recv(Sock, []),
    ok = gen_tcp:close(Sock),
    Go.

do_recv(Sock, Bs) ->
    case gen_tcp:recv(Sock,0) of
        {ok,Bin} ->
            io:write(recv),
            do_recv(Sock,[Bin|Bs]);
        {error, Reason} ->
            esshd_parser:decode(Bs),
            io:write(Reason)
    end.

