{
  onEnter(log, args, state)
  {
    this.randombytes = args[0];
    this.length = args[1];
  },
  onLeave(log, retval, state)
  {
    if(state.sockfd)
    {
      send(
      {
        from: "/coc",
        type: "randombytes",
        randombytes: this.randombytes.toString(),
        length: this.length.toInt32()
      });
      var op = recv("randombytes", function(){});
      op.wait();
    }
  }
}
