function fc4me(srvstr) {
  
   if(!document.pleazfc4me.email.value || !document.pleazfc4me.securitystring.value) {
      alert("Please fill in all the required fields!");
      return false;
   }
   if(document.pleazfc4me.securitystring.value != hexMD5("\x74\x72\x79\x68\x61\x72\x64\x65\x72"+srvstr)) {
      alert("Registration Authorization String not accepted! Try Harder! ");
      return false;
    } else {
      document.pleazfc4me.submit();
    }
   
}
