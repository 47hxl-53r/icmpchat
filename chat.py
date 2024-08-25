import random
import threading
from scapy.all import IP, ICMP, Raw, send, sniff


# Function to generate a random username
def generateRandomUsername():
    return str(random.randint(1000, 9999))


# Function to encode in caesar cipher with specified shifts (Can be used to decode using negative shifts)
def caesarEncode(message, shift):
    result = ""
    for char in message:
        if char.isalpha():
            isUpper = char.isupper()
            shiftedChar = chr((ord(char) - ord('A' if isUpper else 'a') + shift) % 26 + ord('A' if isUpper else 'a'))
            result += shiftedChar
        else:
            result += char
    return result


# Function to send ICMP message
def sendICMPMessage(destinationIp, username, message):
    message = f"{username}: {message}"
    encodedMessage = caesarEncode(message, 4)
    packet = IP(dst=destinationIp) / ICMP() / encodedMessage
    send(packet, verbose=False)



# Function to process a recieved ICMP packet
def processICMPPacket(packet, ownUsername):
    if ICMP in packet and packet[ICMP].type == 8:                 # ICMP echo message
        if Raw in packet:
            try:                                         # If there is any data in the ICMP packets we decode it.
                data = packet[Raw].load.decode('utf-8', 'ignore')
                decoded_data = caesarEncode(data, -4)                 # Using negative shifts to decode the encoded cipher.
                username, message = decoded_data.split(": ", 1)
                if username != ownUsername:                           # Trick to not print our own message
                    print(f"{username}: {message}")
                    print("> ", end="", flush=True)  
            except:
                pass



# Function to listen ICMP packets and forward the recieved packets to processICMPPacket function.
def listenICMPPackets(own_username):
    sniff(prn=lambda packet: processICMPPacket(packet, own_username), filter="icmp", store=0)



if __name__ == "__main__":
    destinationIP = "127.0.0.1"
    ownUsername = generateRandomUsername()
    listenerThread = threading.Thread(target=listenICMPPackets, args=(ownUsername,), daemon=True)  # Using a different thread to listen for ICMP packets
    listenerThread.start()

    print(f"Your username is: {ownUsername}")


    while True:
        message = input("> ")
        if message.lower() == 'exit':
            break
        sendICMPMessage(destinationIP, ownUsername, message)
