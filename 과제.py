import socket
import argparse
from struct import pack
import select

# 기본 설정 값들
DEFAULT_PORT = 69
BLOCK_SIZE = 512
DEFAULT_TRANSFER_MODE = 'octet'
TIMEOUT = 1  # 1초 타임아웃

# TFTP 명령 코드 및 전송 모드
OPCODE = {'RRQ': 1, 'WRQ': 2, 'DATA': 3, 'ACK': 4, 'ERROR': 5}
MODE = {'netascii': 1, 'octet': 2, 'mail': 3}

# TFTP 오류 코드
ERROR_CODE = {
    0: "정의되지 않음, 에러 메시지 참조 (있을 경우).",
    1: "파일을 찾을 수 없음.",
    2: "접근 거부.",
    3: "디스크 가득 참 또는 할당 초과.",
    4: "잘못된 TFTP 동작.",
    5: "알 수 없는 전송 ID.",
    6: "파일이 이미 존재합니다.",
    7: "사용자가 없습니다."
}

# 파일 전송 요청 보내기
def send_wrq(filename, mode, sock, server_address):
    format = f'>h{len(filename)}sB{len(mode)}sB'
    wrq_message = pack(format, OPCODE['WRQ'], bytes(filename, 'utf-8'), 0, bytes(mode, 'utf-8'), 0)

    # 첫번째: 클라이언트가 WRQ 패킷을 서버에 전송
    sock.sendto(wrq_message, server_address)
    print("WRQ 패킷을 서버에 전송했습니다.")

    try:
        # 두번째 2: 서버는 해당 파일을 생성하고, 첫 번째 ACK 패킷을 전송
        ack_data, server_new_socket = sock.recvfrom(516)
        ack_opcode = int.from_bytes(ack_data[:2], 'big')

        if ack_opcode == OPCODE['ACK']:
            block_number = int.from_bytes(ack_data[2:4], 'big')
            print(f"서버로부터 ACK 패킷을 받았습니다. 블록 번호: {block_number}")
        else:
            print("서버로부터 예상치 못한 응답을 받았습니다.")
            return
    except socket.timeout:
        print("타임아웃: 서버로부터 ACK를 기다리는 동안 시간이 초과되었습니다.")
        return

    # 세번째: 클라이언트는 ACK 패킷을 받고, 첫 번째 데이터 패킷을 전송하고, 서버는 데이터 패킷을 받으면, ACK 패킷을 전송하여 데이터 패킷이 제대로 도착했음을 알림
    try:
        with open(filename, 'rb') as file:
            block_number = 1
            file_block = file.read(BLOCK_SIZE)

            while file_block:
                data_packet = pack(f'>hh{len(file_block)}s', OPCODE['DATA'], block_number, file_block)
                sock.sendto(data_packet, server_new_socket)
                print(f"데이터 패킷을 서버에 전송했습니다. 블록 번호: {block_number}")

                # ACK 패킷 대기
                ack_data, _ = sock.recvfrom(516)
                ack_opcode = int.from_bytes(ack_data[:2], 'big')

                if ack_opcode == OPCODE['ACK']:
                    block_number = int.from_bytes(ack_data[2:4], 'big')
                    print(f"서버로부터 ACK 패킷을 받았습니다. 블록 번호: {block_number}")
                else:
                    print("서버로부터 예상치 못한 응답을 받았습니다.")
                    return

                file_block = file.read(BLOCK_SIZE)

            print("모든 데이터 패킷 전송이 완료되었습니다.")
    except socket.timeout:
        print("타임아웃: 데이터 패킷을 기다리는 동안 시간이 초과되었습니다.")
        return

# 파일 데이터 수신
def receive_data(filename, mode, sock, server_address):
    format = f'>h{len(filename)}sB{len(mode)}sB'
    rrq_message = pack(format, OPCODE['RRQ'], bytes(filename, 'utf-8'), 0, bytes(mode, 'utf-8'), 0)
    sock.sendto(rrq_message, server_address)

    try:
        with open(filename, 'wb') as file:
            expected_block_number = 1

            while True:
                # 타임아웃 구현을 위해 select 사용
                ready, _, _ = select.select([sock], [], [], TIMEOUT)

                if not ready:
                    print("Timeout occurred. Resending last ACK.")
                    send_ack(expected_block_number - 1, server_address)
                    continue

                # 서버로부터 데이터 수신
                # 서버는 데이터를 전송하기 위해 새로 할당된 포트를 사용하므로
                # ACK는 새로운 소켓에 전송되어야 함
                data, server_new_socket = sock.recvfrom(516)
                opcode = int.from_bytes(data[:2], 'big')

                # 메시지 타입 확인
                if opcode == OPCODE['DATA']:
                    block_number = int.from_bytes(data[2:4], 'big')
                    if block_number == expected_block_number:
                        send_ack(block_number, server_new_socket)
                        file_block = data[4:]
                        file.write(file_block)
                        expected_block_number += 1
                        print(file_block.decode())
                    else:
                        send_ack(block_number, server_new_socket)

                elif opcode == OPCODE['ERROR']:
                    error_code = int.from_bytes(data[2:4], byteorder='big')
                    print(ERROR_CODE.get(error_code, "알 수 없는 오류"))
                    break

                else:
                    break

                if len(file_block) < BLOCK_SIZE:
                    file.close()
                    print("파일 전송 완료.")
                    break
    except socket.timeout:
        print("Timeout occurred. File transfer failed.")
    except Exception as e:
        print(f"오류 발생: {e}")

# ACK 메시지 전송
def send_ack(seq_num, server):
    format = f'>hh'
    ack_message = pack(format, OPCODE['ACK'], seq_num)
    sock.sendto(ack_message, server)
    print(f"블록 번호 {seq_num}에 대한 ACK를 전송했습니다.")

# 명령행 인자 파싱
parser = argparse.ArgumentParser(description='TFTP 클라이언트 프로그램')
parser.add_argument(dest="host", help="서버 IP 주소", type=str)
parser.add_argument(dest="operation", help="파일을 가져오거나 업로드합니다 ('get' 또는 'put')", type=str)
parser.add_argument(dest="filename", help="전송할 파일의 이름", type=str)
parser.add_argument("-p", "--port", dest="port", type=int)
args = parser.parse_args()

# UDP 소켓 생성
server_ip = args.host
server_port = args.port if args.port is not None else DEFAULT_PORT
server_address = (server_ip, server_port)
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(TIMEOUT)

mode = DEFAULT_TRANSFER_MODE
operation = args.operation
filename = args.filename

# 파일 전송 또는 수신 작업 수행
if operation.lower() == 'put':
    send_wrq(filename, mode, sock, server_address)
elif operation.lower() == 'get':
    receive_data(filename, mode, sock, server_address)
else:
    print("올바른 작업을 선택하세요 ('put' 또는 'get').")

# 소켓 닫기
sock.close()