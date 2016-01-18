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
      if(this.length == 7)
      {
        state.messageid = state.hexdump(this.buffer, 2);
      }
      else
      {
        if(this.length > 0 && state.header)
        {
          state.buffer = state.hexdump(this.buffer, this.length.toInt32());
          if(state.messageid == "4e84")
          {
            send(
            {
              from: "/coc",
              type: "recv",
              messageid: state.messageid,
              buffer: state.hexdump(this.buffer, this.length.toInt32())
            });
            state.messageid = false;
            state.header = false;
            state.buffer = false;
          }
        }
      }
    }
  }
}
