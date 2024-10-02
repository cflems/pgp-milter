import config
import utils
import Milter
import email

class PGPMilter(Milter.Base):
  def __init__(self):
    self.recipients = []
    self.headers = []
    self.content = bytes()

  @Milter.noreply
  def connect(_self, _ip_name, _family, _hostaddr):
    return Milter.CONTINUE

  @Milter.noreply
  def envfrom(self, name, *esmtp_params):
    self.__init__()
    return Milter.CONTINUE

  @Milter.noreply
  def envrcpt(self, name, *strings):
    self.recipients.append(name)
    return Milter.CONTINUE

  @Milter.noreply
  def header(self, k: str, v: str):
    self.headers.append((k.encode(), v.encode()))
    return Milter.CONTINUE

  def eoh(self):
    return Milter.CONTINUE

  def body(self, chunk):
    self.content += chunk
    return Milter.CONTINUE

  def eom(self):
    print('Encrypting message to recipients: [%s]' % ', '.join(self.recipients))

    raw_headers = b'\n'.join(map(lambda header : b'%s: %s' % header, self.headers))
    msg = email.message_from_bytes(raw_headers + b'\n\n' + self.content,\
                                   policy=email.policy.default)

    if b'-----BEGIN PGP MESSAGE-----' in self.content or utils.already_encrypted(msg):
      print('Already encrypted, passing through.')
      return Milter.ACCEPT

    enc_msg, encrypted = utils.encrypt(msg, self.recipients)
    if not encrypted:
      print('No keys found, passing through.')
      return Milter.ACCEPT

    # `Content-Transfer-Encoding: quoted-printable`
    # can prevent the message from being decrypted by clients 
    self.set_header(msg, 'Content-Transfer-Encoding', '')
    for (k, v) in enc_msg.items():
      self.set_header(msg, k, v)

    enc_bytes = enc_msg.as_bytes()
    enc_body = enc_bytes[enc_bytes.find(b'\n\n')+2:]
    self.replacebody(enc_body)

    return Milter.ACCEPT

  def close(self):
    self.__init__()
    return Milter.CONTINUE

  def set_header(self, old_msg, k, v):
    old_headers = old_msg.get_all(k)
    if old_headers != None:
      for i in range(len(old_headers)-1, -1, -1):
        self.chgheader(k, i, '')
    if v != None and len(v) > 0:
      self.addheader(k, v)

def main():
  Milter.factory = PGPMilter
  Milter.set_flags(Milter.ADDHDRS + Milter.CHGHDRS + Milter.CHGBODY)
  Milter.runmilter('cmail-pgp-milter', config.socket)

if __name__ == '__main__':
  print('Starting CMail PGP Milter')
  main()
