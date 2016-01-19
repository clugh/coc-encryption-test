{
  onEnter(log, args, state)
  {
    this.sockfd = args[0];
    this.buffer = args[1];
    this.length = args[2];
    this.flags = args[3];
  },
  onLeave(log, retval, state)
  {
    if(state.sockfd && this.sockfd.equals(state.sockfd))
    {
      if(this.length > 0)
      {
        if(state.messageid)
        {
          send(
          {
            from: "/coc",
            type: "recv",
            messageid: state.messageid,
            buffer: state.hexdump(this.buffer, this.length.toInt32())
          });
          state.messageid = false;
        }
        else if(this.length == 7)
        {
          state.messageid = state.hexdump(this.buffer, 2);
        }
      }
    }
  }
}
