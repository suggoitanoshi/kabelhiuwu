# Kabel Hiu
Packet Sniffer sederhana yang mengenali paket TCP, UDP, dan ICMP
Cara penggunaan: `python kabelhiu.py [output file]`
Output file adalah nama file optional, apabila tidak diberikan maka packet yang diterima akan dikeluarkan ke standard output.
Pemilihan interface dan jenis paket dilakukan secara interaktif dalam script. Sebagai tambahan, untuk menerima semua paket,
dapat dimasukkan nilai sembarang yang tidak terdapat pada list. Selain itu, untuk menerima paket tertentu dapat dimasukkan angka
paket, dipisahkan oleh koma. (contoh: `1,2`)