import key_loader
import pgpy
import email
from email.message import EmailMessage
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
from email.mime.text import MIMEText
from copy import deepcopy
from random import choices as alphabet_random
from string import ascii_letters, digits

protected_headers = ['to', 'cc', 'from', 'reply-to', 'followup-to', 'subject', 'date',\
                     'message-id']
structural_headers = ['content-type']
overzealous_headers = ['mime-version', 'content-transfer-encoding']

def encrypt(msg: EmailMessage, recipients: list[str]) -> tuple[EmailMessage, bool]:
  payload = wrap_body(deepcopy(msg))

  rcpt_keys = load_keys(recipients)
  if len(rcpt_keys) < 1:
    return msg, False

  try:
    enc_msg = pgpy.PGPMessage.new(payload.as_string())
    for key in rcpt_keys:
      enc_msg = key.encrypt(enc_msg)
  except:
    return msg, False

  container = MIMEMultipart(
    'encrypted',
    boundary=gen_boundary(),
    protocol='application/pgp-encrypted'
  )
  container.preamble = 'This is an OpenPGP/MIME encrypted message (RFC 4880 and 3156)'

  part1 = MIMEApplication(
    _data='Version: 1\n',
    _subtype='pgp-encrypted',
    _encoder=email.encoders.encode_7or8bit
  )
  part1['Content-Description'] = 'PGP/MIME version identification'

  part2 = MIMEApplication(
    _data=str(enc_msg),
    _subtype='octet-stream; name="encrypted.asc"',
    _encoder=email.encoders.encode_7or8bit
  )
  part2['Content-Description'] = 'OpenPGP encrypted message'
  part2['Content-Disposition'] = 'inline; filename="encrypted.asc"'

  strip_extraneous_headers(part1)
  strip_extraneous_headers(part2)
  container.attach(part1)
  container.attach(part2)
  strip_extraneous_headers(container, ['mime-version'])
  return container, True

def already_encrypted(msg: EmailMessage) -> bool:
  if msg.get_content_type() in ['multipart/encrypted', 'application/pgp-encrypted']:
    return True
  for part in msg.iter_parts():
    if already_encrypted(part):
      return True
  return False

def wrap_body(msg: EmailMessage) -> EmailMessage:
  wrapped_msg = MIMEMultipart('mixed', boundary=gen_boundary(), protected_headers='v1')
  strip_extraneous_headers(wrapped_msg, overzealous_headers + protected_headers)
  copy_headers(msg, wrapped_msg, protected_headers)

  if msg.is_multipart():
    strip_extraneous_headers(wrapped_msg, structural_headers)
    copy_headers(msg, wrapped_msg, structural_headers)
    wrapped_msg.set_payload(msg.get_payload(decode=False))
  else:
    text_holder = MIMEText(msg.get_payload(decode=True), _charset='utf-8')
    strip_extraneous_headers(text_holder, structural_headers)
    copy_headers(msg, text_holder, structural_headers)
    wrapped_msg.attach(text_holder)

  return wrapped_msg

def copy_headers(orig_msg: EmailMessage, container: EmailMessage, headers: list) -> None:
  for (header, value) in orig_msg.items():
    if header.lower() in headers:
      container.add_header(header, value)

def strip_extraneous_headers(msg: EmailMessage, strip_headers=overzealous_headers) -> None:
  for header in msg.keys():
    if header.lower() in strip_headers:
      del msg[header]

def gen_boundary() -> str:
  return '-' * 12 + ''.join(alphabet_random(ascii_letters + digits, k=24))

def load_keys(recipients: list[str]) -> list[pgpy.PGPKey]:
  addrs = []
  for recipient in recipients:
    _display_name, addr = email.utils.parseaddr(recipient)
    addrs.append(addr)
  return key_loader.load_keys(addrs)
