# **Hướng Dẫn Sử Dụng Kerberos Simulation**

## **Giới Thiệu**  
Dự án **Kerberos Simulation** là một chương trình mô phỏng giao thức Kerberos sử dụng ngôn ngữ lập trình C++ và thư viện OpenSSL. Chương trình bao gồm ba thành phần chính:  

- **Authentication Server (AS)** – Xác thực người dùng và cấp **Ticket Granting Ticket (TGT)**.  
- **Ticket Granting Server (TGS)** – Cung cấp **Service Ticket** dựa trên TGT.  
- **Service Server (SS)** – Xác thực người dùng để truy cập dịch vụ.  

Chương trình sử dụng cơ chế mã hóa đối xứng để bảo vệ thông tin đăng nhập và quá trình xác thực.

---

## **Cấu Trúc Dự Án**  
Thư mục dự án bao gồm các thành phần sau:  

- **`src/`**: Chứa toàn bộ mã nguồn của chương trình.  
  - `main.cpp`: Chương trình chính, giao diện dòng lệnh cho người dùng.  
  - `authentication_server.cpp`: Xử lý xác thực và cấp TGT.  
  - `ticket_granting_server.cpp`: Xử lý yêu cầu cấp Service Ticket.  
  - `service_server.cpp`: Xử lý xác thực và cung cấp dịch vụ.  
  - `encryption.cpp`: Cung cấp các hàm mã hóa và giải mã bằng OpenSSL.  
  - `kerberos_protocol.cpp`: Mô phỏng luồng hoạt động của giao thức Kerberos.  
  - `kerberos_protocol.h`: Khai báo các hàm mô phỏng Kerberos.  
  - `encryption.h`: Định nghĩa các hàm mã hóa và bảo mật.  

- **`include/`**: Chứa các file header để tổ chức mã nguồn.  
  - `authentication_server.h`, `ticket_granting_server.h`, `service_server.h`: Định nghĩa các chức năng của từng thành phần.  

- **`CMakeLists.txt`**: File cấu hình CMake để biên dịch chương trình.  
- **`README.md`**: Tài liệu hướng dẫn sử dụng và cài đặt.  
- **`build/`**: Thư mục chứa file biên dịch sau khi chương trình được build.  

---

## **Cài Đặt Môi Trường**  

### **1. Cài Đặt OpenSSL bằng Vcpkg**  
Chương trình sử dụng OpenSSL để thực hiện mã hóa dữ liệu. Nếu bạn chưa cài đặt **Vcpkg**, hãy làm theo các bước sau:  

1. **Tải về và cài đặt Vcpkg**  
   ```sh
   git clone https://github.com/microsoft/vcpkg.git
   cd vcpkg
   ./bootstrap-vcpkg.bat  # Windows
   ./bootstrap-vcpkg.sh   # Linux/macOS
   ```

2. **Cài đặt OpenSSL**  
   - Trên Windows:  
     ```sh
     vcpkg install openssl:x64-windows
     ```
   - Trên Linux/macOS:  
     ```sh
     vcpkg install openssl
     ```

---

## **Hướng Dẫn Build & Chạy Chương Trình**  

### **2. Build với CMake**  
Sau khi đã cài đặt **OpenSSL**, tiến hành build chương trình bằng CMake như sau:  

1. **Tạo thư mục build** và chuyển vào thư mục này:  
   ```sh
   mkdir build
   cd build
   ```

2. **Chạy CMake để cấu hình build**  
   ```sh
   cmake .. -DCMAKE_TOOLCHAIN_FILE="C:/path/to/vcpkg/scripts/buildsystems/vcpkg.cmake"
   ```

   - Nếu dùng **Windows**, thay đổi đường dẫn phù hợp:  
     ```sh
     cmake .. -DCMAKE_TOOLCHAIN_FILE=C:/Users/your_user/vcpkg/scripts/buildsystems/vcpkg.cmake
     ```

3. **Tiến hành build chương trình**  
   ```sh
   cmake --build .
   ```

---

### **3. Chạy Chương Trình**  
Sau khi build thành công, chạy chương trình như sau:  

- Trên Linux/macOS:  
  ```sh
  ./kerberos_sim
  ```

- Trên Windows:  
  ```sh
  kerberos_sim.exe
  ```

---

## **Hướng Dẫn Sử Dụng**  
Chương trình mô phỏng giao thức Kerberos với các bước sau:  

1. **Người dùng đăng nhập** vào hệ thống và gửi yêu cầu xác thực đến Authentication Server (AS).  
2. **AS cấp Ticket Granting Ticket (TGT)** nếu thông tin hợp lệ.  
3. **Người dùng yêu cầu Service Ticket từ TGS** bằng cách gửi TGT.  
4. **TGS cấp Service Ticket** cho phép truy cập dịch vụ.  
5. **Người dùng gửi Service Ticket đến Service Server (SS)** để xác thực và truy cập tài nguyên.  

Nếu xác thực thành công, người dùng có thể truy cập dịch vụ; nếu thất bại, hệ thống sẽ từ chối truy cập.

---

## **Ghi Chú & Debug**  
- Nếu gặp lỗi `cannot open source file "openssl/evp.h"`, kiểm tra lại OpenSSL đã được cài đặt bằng lệnh:  
  ```sh
  vcpkg list | findstr openssl
  ```
- Đảm bảo **CMake đang sử dụng Vcpkg** làm toolchain đúng cách.  
- Nếu build thất bại, kiểm tra log lỗi và xác nhận **CMakeLists.txt** có cấu hình đúng thư viện.  

---

Hướng dẫn trên giúp bạn cài đặt, build và chạy chương trình mô phỏng Kerberos một cách dễ dàng. Nếu cần thêm thông tin, hãy liên hệ với nhóm phát triển. 🚀