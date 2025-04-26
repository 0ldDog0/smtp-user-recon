#!/usr/bin/env python3
from pwn import *
import sys
import time


def get_connection(smtp_server):
    try:
        # Create connection with timeout
        conn = remote(smtp_server, 25, timeout=5)

        # Read initial banner (220 message)
        banner = conn.recvuntil(b'\n',timeout=13).decode().strip()
        print(f"[*] Server banner: {banner}")
        
        if not banner.startswith('220'):
            print(f"[!] Unexpected banner: {banner}")

        
        # Send HELO and get response
        print("[*] Sending HELO command...")
        conn.sendline(b'HELO example.com')
        helo_response = conn.recvuntil(b'\n').decode().strip()
        print(f"[*] HELO response: {helo_response}")
        
        # Check if server accepted our HELO
        if not helo_response.startswith('250'):
            print(f"[!] Server did not accept HELO command: {helo_response}")
            conn.close()
            return None
        
        return conn
    except Exception as e:
        print(f"[!] Error establishing connection: {str(e)}")
        return None

def get_users(smtp_server, wordlist_file):
    try:
        # Create connection with timeout
        conn = get_connection(smtp_server)


        valid_users = []
        try:
            with open(wordlist_file, 'r') as wordlist:
                usernames = [line.strip() for line in wordlist if line.strip()]
                
                print(f"[*] Testing {len(usernames)} usernames...")
                
                i = 0
                while i < len(usernames):
                    username = usernames[i]
                    retry = False
                    
                    try:
                        # Send VRFY
                        vrfy_cmd = f'VRFY {username}'.encode()
                        conn.sendline(vrfy_cmd)
                        response = conn.recvuntil(b'\n', timeout=2).decode().strip()
                        # print (response) #for debug
                        # Check response
                        if "252" in response and "2.0.0" in response:
                            print(f"[+] Valid User: {username}")
                            valid_users.append(username)
                        elif "550" in response and "5.1.1" in response:
                            print(f"[-] Invalid User: {username}")
                        elif "421" in response and "too many errors" in response:
                            print(f"[!] Server limiting connections: {response}")
                            print(f"[*] Reconnecting and continuing with username: {username}")
                            
                            # Close current connection
                            try:
                                conn.close()
                            except:
                                pass
                                
                            # Wait before reconnecting
                            time.sleep(5)
                            
                            # Get new connection
                            conn = get_connection(smtp_server)
                            if not conn:
                                print("[!] Failed to reconnect. Exiting.")
                                return valid_users
                                
                            # Set retry flag to retry the current username
                            retry = True
                        else:
                            print(f"[?] Response for {username}: {response}")
                        
                        # Only increment if we're not retrying
                        if not retry:
                            i += 1
                            
                            # # Longer delay to avoid overwhelming the server
                            # time.sleep(0.5)
                            
                            # # Every 10 requests, pause longer to avoid triggering limits
                            # if i > 0 and i % 10 == 0:
                            #     print(f"[*] Pausing after {i} requests...")
                            #     time.sleep(2)
                    
                    except EOFError:
                        print(f"[!] Connection closed by server after testing {i+1}/{len(usernames)} usernames")
                        
                        # Try to reconnect
                        print(f"[*] Attempting to reconnect...")
                        time.sleep(5)
                        conn = get_connection(smtp_server)
                        if not conn:
                            print("[!] Failed to reconnect. Exiting.")
                            return valid_users
                            
                        # Don't increment i, retry the current username
                        retry = True
                        
                    except Exception as e:
                        print(f"[!] Error while testing {username}: {str(e)}")
                        
                        # Try to reconnect
                        print(f"[*] Attempting to reconnect...")
                        time.sleep(5)
                        conn = get_connection(smtp_server)
                        if not conn:
                            print("[!] Failed to reconnect. Exiting.")
                            return valid_users
                            
                        # Don't increment i, retry the current username
                        retry = True
            
            # Send QUIT and close after testing all usernames
            try:
                conn.sendline(b'QUIT')
                conn.close()
            except:
                pass
                
            return valid_users
        except FileNotFoundError:
            print(f"[!] Wordlist not found at {wordlist_file}!")
            conn.close()
            sys.exit(1)
      
    except Exception as e:
        print(f"[!] Error: {str(e)}")
        try:
            conn.close()
        except:
            pass
        return []

def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <SMTP Server> <Path to Wordlist>")
        sys.exit(1)
        
    smtp_server = sys.argv[1]
    wordlist_file = sys.argv[2]
    
    print(f"[*] Starting SMTP VRFY scan on {smtp_server}")
    print(f"[*] Using wordlist: {wordlist_file}")
    
    valid_users = get_users(smtp_server, wordlist_file)
    
    if valid_users:
        print(f"\n[+] Found {len(valid_users)} valid users:")
        for user in valid_users:
            print(f"    - {user}")
    else:
        print("\n[-] No valid users found")


if __name__ == "__main__":
    main()
