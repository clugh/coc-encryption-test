{
  onEnter(log, args, state)
  {
    this.message = args[0];
    this.ciphertext = args[1];
    this.length = args[2];
    this.unknown = args[3];
    this.nonce = args[4];
    this.k = args[5];
    if(state.messageid && state.messageid)
    {
      state.ciphertext = state.hexdump(this.ciphertext.add(16), this.length.toInt32() - 16);
    }
  },
  onLeave(log, retval, state)
  {
    if(state.sockfd && state.messageid)
    {
      send(
      {
        from: "/coc",
        type: "recv",
        messageid: state.messageid,
        message: state.hexdump(this.message.add(32), this.length.toInt32() - 32),
        k: state.hexdump(this.k, 32),
        nonce: state.hexdump(this.nonce, 24),
        ciphertext: state.ciphertext,
        buffer: state.buffer
      });
      state.messageid = false;
      state.header = false;
      state.ciphertext = false;
      state.buffer = false;
    }
  }
}
