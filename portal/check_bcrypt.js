const bcrypt = require('bcrypt');
const hash = '$2b$10$DDN0DoYRR7G6R0Mj6YlemeBLRZ6juETwvBGWJ9o6hCw9cPJeP5igC';
const candidates = [
  'temporary','admin123','manager123','password','hunter','sparq','Password123!','Welcome123',
  'SparQ123!','Sparqd123!','getsparqd','Portal123!','letmein','P@ssw0rd','P@ssword1','TempPass1!',
  'TempPass123','changeme','changeme123','Admin@123','Summer2024','Winter2024','Qwerty123','Test1234'
];
for (const p of candidates) {
  try { console.log(p, bcrypt.compareSync(p, hash)); } catch (e) { console.error('error', p, e.message); }
}
