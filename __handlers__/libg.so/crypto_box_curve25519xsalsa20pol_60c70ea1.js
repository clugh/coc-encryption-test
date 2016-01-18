{
  onEnter(log, args, state)
  {
    this.k = args[0];
    this.serverkey = args[1];
    this.sk = args[2];
    if(state.sockfd)
    {
      state.serverkey = state.hexdump(this.serverkey, 32);
      state.sk = state.hexdump(this.sk, 32)
    }
  },
  onLeave(log, retval, state)
  {
    if(state.sockfd)
    {
      send(
      {
        from: "/coc",
        type: "beforenm",
        k: state.hexdump(this.k, 32),
        serverkey: state.serverkey,
        sk: state.sk
      });
      state.serverkey = false;
      state.sk = false;
    }
  }
}
