{
  onEnter(log, args, state)
  {
    this.sockfd = args[0];
    this.buffer = args[1];
    this.length = args[2];
    this.flags = args[3];
    if(!state.hexdump)
    {
      state.hexdump = function(pointer, length)
      {
        buf = Memory.readByteArray(pointer, length);
        arr = new Uint8Array(buf);
        hex = '';
        for(var i = 0; i < arr.length; i++)
        {
          byte = (arr[i] & 0xff).toString(16);
          byte = (byte.length === 1) ? '0' + byte : byte;
          hex += byte;
        }
        return hex;
      }
    }
    messageid = state.hexdump(this.buffer, 2);
    if(!state.sockfd && messageid == "2774")
    {
      state.sockfd = this.sockfd;
      send(
      {
        from: "/coc",
        type: "socket",
        threadid: Process.getCurrentThreadId()
      });
      state.recv = function()
      {
        recv("log", function(value)
        {
          log(value.message)
          state.recv();
        });
      };
      state.recv();
      state.recv.wait();
    }
    if(state.sockfd && this.sockfd.equals(state.sockfd) && this.length > 0)
    {
      send(
      {
        from: "/coc",
        type: "send",
        messageid: messageid,
        message: state.message,
        k: state.k,
        nonce: state.nonce,
        ciphertext: state.ciphertext,
        buffer: state.hexdump(this.buffer.add(7), this.length.toInt32() - 7)
      });
      state.message = false;
      state.k = false;
      state.nonce = false;
      state.ciphertext = false;
    }
  }
}
