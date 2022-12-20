# DNS Server
Rust Dasturlash tilida yozilgan DNS Server

Ushbu loyiha Rust dasturlash tilida yoziladigan boshqa dns-server uchun asos bo'lishi mumkin.
Bu loyihada DNS Server asosi yani boshlang'ich yozilgan siz uni rivojlantirishingiz va DNS Server sifatida foydalanishingiz mumkin.

![alt text](https://github.com/ismoilovdevml/dns-server/blob/master/assets/dns-server.png)


Salomlashish :)

```bash
dig +short @127.0.0.1 -p 1053 ismoilovdev.hello.dnsserver.dev
```

Counter Aniqlash
```bash
dig +short @127.0.0.1 -p 1053 counter.dnsserver.dev

```

My IP

```bash
dig +short @127.0.0.1 -p 1053 myip.dnsserver.dev
```


Foydalanilgan texnalogiyalar:
* [clap](https://docs.rs/clap/latest/clap/)
* [trust-dns-server](https://trust-dns.org/)
* [tokio](https://tokio.rs/)
  
