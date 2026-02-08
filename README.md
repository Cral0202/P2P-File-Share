**Receiving files requires a public IP address. It will not work if you are behind CG-NAT. However, you can still
send files without a public IP address.**

---

- All data is sent encrypted over a TLS connection.

- Ports need to be opened on your network to allow file receiving.
  If UPnP is enabled on your network, the program will automatically open and close the ports of your choosing.
  Otherwise, you will have to manually open ports if you want to receive files.
  No ports need to be opened in order to send files.

- To connect to someone, add them as a contact and make sure they’ve added you as well.
  Then you can select them and press "Connect".
  You can then select a file and click "Send".
  You will be notified if the recipient rejects the file, or receives it.

- To receive files, click the "Enable Receiving" button. When a file is sent to you, you can choose to either receive or reject it.
  Received files are placed in your "Downloads" folder.

- To send folders, package them first (e.g., ZIP), then send them as a regular file.

---

If you want to build an executable: `pyinstaller main.spec`

### **Program images:**

![Receive image](assets/receive_demo_image.png)
![Send image](assets/send_demo_image.png)
