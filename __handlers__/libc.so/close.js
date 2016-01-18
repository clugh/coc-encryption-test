{
  onEnter(log, args, state)
  {
    this.fd = args[0];
    if(state.sockfd && this.fd.equals(state.sockfd))
    {
      state.sockfd = false;
      send(
      {
        from: "/coc",
        type: "close",
      });
    }
  }
}
