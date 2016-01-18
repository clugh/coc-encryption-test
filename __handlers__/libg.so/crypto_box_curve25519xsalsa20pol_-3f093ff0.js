{
  onEnter(log, args, state)
  {
    this.ciphertext = args[0];
    this.message = args[1];
    this.length = args[2];
    this.unknown = args[3];
    this.nonce = args[4];
    this.k = args[5];
    if(state.sockfd)
    {
      state.message = state.hexdump(this.message.add(32), this.length.toInt32() - 32);
      state.k = state.hexdump(this.k, 32);
      state.nonce = state.hexdump(this.nonce, 24);
    }
  },
  onLeave(log, retval, state)
  {
    if(state.sockfd)
    {
      state.ciphertext = state.hexdump(this.ciphertext.add(16), this.length.toInt32() - 16);
    }
  }
}
