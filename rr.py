import socket
import threading
import time
import json
import hashlib
import hmac
import secrets
from datetime import datetime
import sys
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import getpass
from collections import defaultdict, deque
import re

# Try to import colorama for cross-platform color support
try:
    from colorama import init, Fore, Back, Style, Cursor
    init()
    COLORAMA_AVAILABLE = True
except ImportError:
    COLORAMA_AVAILABLE = False
    # Fallback colors (may not work on all terminals)
    class Fore:
        BLACK = RED = GREEN = YELLOW = BLUE = MAGENTA = CYAN = WHITE = RESET = ''
    class Back:
        BLACK = RED = GREEN = YELLOW = BLUE = MAGENTA = CYAN = WHITE = RESET = ''
    class Style:
        BRIGHT = DIM = NORMAL = RESET_ALL = ''

class EthicalFilter:
    """Implements ethical content filtering and moderation"""
    
    def __init__(self):
        # Define prohibited content patterns
        self.prohibited_patterns = [
            r'\b(hate|racist|sexist|bigot)\b',
            r'\b(kill|murder|harm|violence)\b.*\b(you|your|them)\b',
            r'\b(dox|doxing|personal info|address|phone)\b',
            r'\b(threat|threaten|hurt)\b.*\b(you|someone)\b'
        ]
        
        # Warning levels and responses
        self.warning_levels = {
            'low': "Please maintain respectful conversation.",
            'medium': "Warning: Content approaching community guidelines violation.",
            'high': "BLOCKED: Message violates ethical guidelines and was not sent."
        }
        
        self.user_warnings = defaultdict(int)
        self.max_warnings = 3
        
    def scan_message(self, message, username):
        """Scan message for ethical violations"""
        message_lower = message.lower()
        
        # Check for prohibited patterns
        severity_score = 0
        violations = []
        
        for pattern in self.prohibited_patterns:
            if re.search(pattern, message_lower, re.IGNORECASE):
                severity_score += 1
                violations.append(pattern)
        
        # Determine action based on severity
        if severity_score >= 2:
            self.user_warnings[username] += 2
            return 'high', violations
        elif severity_score == 1:
            self.user_warnings[username] += 1
            return 'medium', violations
        else:
            return 'low', []
    
    def check_user_status(self, username):
        """Check if user has exceeded warning limits"""
        return self.user_warnings.get(username, 0) >= self.max_warnings
    
    def get_warning_message(self, level):
        """Get appropriate warning message"""
        return self.warning_levels.get(level, "")

class TransparencyLogger:
    """Maintains transparent moderation logs"""
    
    def __init__(self):
        self.moderation_log = deque(maxlen=1000)  # Keep last 1000 actions
        self.consent_given = False
        
    def log_action(self, action_type, username, details, moderator="System"):
        """Log moderation action with timestamp"""
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'action': action_type,
            'user': username,
            'details': details,
            'moderator': moderator
        }
        self.moderation_log.append(log_entry)
        
        # Print to transparent mod log
        print(f"{Fore.YELLOW}[MOD_LOG] {moderator} {action_type} for {username}: {details}{Style.RESET_ALL}")
    
    def get_recent_logs(self, count=10):
        """Get recent moderation logs"""
        return list(self.moderation_log)[-count:]

class CommunityGovernance:
    """Implements community-led governance features"""
    
    def __init__(self):
        self.elected_moderators = set()
        self.user_reports = defaultdict(list)
        self.voting_sessions = {}
        
    def add_report(self, reporter, reported_user, reason, message_content):
        """Add user report to tracking system"""
        report = {
            'reporter': reporter,
            'reported_user': reported_user,
            'reason': reason,
            'message_content': message_content,
            'timestamp': time.time(),
            'status': 'pending'
        }
        self.user_reports[reported_user].append(report)
        
    def can_send_private_message(self, sender, recipient, contact_list):
        """Check if private message is allowed (consent-based)"""
        return recipient in contact_list.get(sender, set())

class DeescalationBot:
    """Automated de-escalation for heated conversations"""
    
    def __init__(self):
        self.heat_metrics = defaultdict(lambda: {'message_count': 0, 'last_heated': 0})
        self.heat_threshold = 5  # Messages in short period
        self.time_window = 60    # 1 minute window
        
    def analyze_conversation_heat(self, username, message):
        """Analyze if conversation is becoming heated"""
        current_time = time.time()
        user_metric = self.heat_metrics[username]
        
        # Check for aggressive language patterns
        aggressive_indicators = [
            r'\b(idiot|stupid|dumb|moron)\b',
            r'(\!+|\?+){3,}',  # Multiple exclamation/question marks
            r'\b(you always|you never)\b',  # Absolute statements
            r'\b(shut up|be quiet)\b'
        ]
        
        is_heated = any(re.search(pattern, message, re.IGNORECASE) 
                       for pattern in aggressive_indicators)
        
        if is_heated:
            user_metric['message_count'] += 1
            user_metric['last_heated'] = current_time
            
        # Clean old entries
        self._clean_old_metrics()
        
        return user_metric['message_count'] >= self.heat_threshold
    
    def get_deescalation_message(self):
        """Get appropriate de-escalation message"""
        messages = [
            "🤝 This conversation seems to be getting intense. Remember to be respectful.",
            "💭 Let's take a moment to breathe and continue this discussion calmly.",
            "🌱 Different perspectives help us grow. Let's maintain constructive dialogue.",
            "⏸️  Consider taking a short break if this discussion is becoming heated."
        ]
        return secrets.choice(messages)
    
    def _clean_old_metrics(self):
        """Clean old heat metrics"""
        current_time = time.time()
        to_remove = []
        
        for user, metric in self.heat_metrics.items():
            if current_time - metric['last_heated'] > self.time_window * 2:
                to_remove.append(user)
        
        for user in to_remove:
            del self.heat_metrics[user]

class SecurityManager:
    """Enhanced security manager with ethical features"""
    
    def __init__(self, password):
        self.password = password.encode()
        self._derive_keys()
        self.message_nonces = set()
        self.max_nonce_age = 300
        
    def _derive_keys(self):
        """Derive encryption and signing keys from password"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b'ethical_lan_messenger',
            iterations=100000,
        )
        key_material = base64.urlsafe_b64encode(kdf.derive(self.password))
        
        self.encryption_key = key_material
        self.signing_key = hashlib.sha256(self.password + b'signing').digest()
        self.fernet = Fernet(self.encryption_key)
    
    def encrypt_message(self, message_data):
        """Encrypt and sign message data with ethical metadata"""
        nonce = secrets.token_hex(16)
        timestamp = time.time()
        
        message_data['nonce'] = nonce
        message_data['timestamp'] = timestamp
        message_data['ethical_hash'] = self._calculate_ethical_hash(message_data)
        
        json_data = json.dumps(message_data).encode()
        encrypted_data = self.fernet.encrypt(json_data)
        
        signature = hmac.new(
            self.signing_key,
            encrypted_data + nonce.encode() + str(timestamp).encode(),
            hashlib.sha256
        ).hexdigest()
        
        return {
            'encrypted_data': base64.urlsafe_b64encode(encrypted_data).decode(),
            'signature': signature,
            'nonce': nonce,
            'timestamp': timestamp
        }
    
    def _calculate_ethical_hash(self, message_data):
        """Calculate hash for message integrity in ethical context"""
        content = message_data.get('text', '') + message_data.get('username', '')
        return hashlib.sha256(content.encode()).hexdigest()
    
    def decrypt_message(self, encrypted_message):
        """Verify signature and decrypt message"""
        try:
            encrypted_data = base64.urlsafe_b64decode(encrypted_message['encrypted_data'])
            signature = encrypted_message['signature']
            nonce = encrypted_message['nonce']
            timestamp = encrypted_message['timestamp']
            
            current_time = time.time()
            if abs(current_time - timestamp) > self.max_nonce_age:
                raise SecurityError("Message timestamp expired")
            
            if nonce in self.message_nonces:
                raise SecurityError("Duplicate message detected")
            
            expected_signature = hmac.new(
                self.signing_key,
                encrypted_data + nonce.encode() + str(timestamp).encode(),
                hashlib.sha256
            ).hexdigest()
            
            if not hmac.compare_digest(signature, expected_signature):
                raise SecurityError("Invalid message signature")
            
            self.message_nonces.add(nonce)
            self._clean_old_nonces()
            
            decrypted_data = self.fernet.decrypt(encrypted_data)
            return json.loads(decrypted_data)
            
        except Exception as e:
            raise SecurityError(f"Decryption failed: {str(e)}")
    
    def _clean_old_nonces(self):
        if len(self.message_nonces) > 1000:
            self.message_nonces = set(list(self.message_nonces)[-500:])

class RateLimiter:
    """Enhanced rate limiter with ethical considerations"""
    
    def __init__(self, max_messages=10, time_window=60):
        self.max_messages = max_messages
        self.time_window = time_window
        self.message_times = deque()
        self.user_limits = defaultdict(lambda: deque())
    
    def check_limit(self, user_id=None):
        current_time = time.time()
        
        while (self.message_times and 
               current_time - self.message_times[0] > self.time_window):
            self.message_times.popleft()
        
        if len(self.message_times) >= self.max_messages:
            return False
        
        if user_id:
            user_times = self.user_limits[user_id]
            while (user_times and 
                   current_time - user_times[0] > self.time_window):
                user_times.popleft()
            
            if len(user_times) >= self.max_messages:
                return False
        
        return True
    
    def record_message(self, user_id=None):
        current_time = time.time()
        self.message_times.append(current_time)
        
        if user_id:
            self.user_limits[user_id].append(current_time)

class SecurityError(Exception):
    pass

class AnimatedDisplay:
    """Enhanced display with ethical messaging"""
    
    def __init__(self):
        self.colors = {
            'system': Fore.CYAN + Style.BRIGHT,
            'success': Fore.GREEN + Style.BRIGHT,
            'error': Fore.RED + Style.BRIGHT,
            'warning': Fore.YELLOW + Style.BRIGHT,
            'user': Fore.MAGENTA + Style.BRIGHT,
            'message': Fore.WHITE + Style.BRIGHT,
            'timestamp': Fore.BLUE + Style.DIM,
            'ethical': Fore.GREEN + Style.BRIGHT,
            'moderation': Fore.YELLOW + Style.BRIGHT,
            'reset': Style.RESET_ALL
        }
        self.animation_frames = ["⣾", "⣽", "⣻", "⢿", "⡿", "⣟", "⣯", "⣷"]
        self.current_frame = 0
    
    def print_ethical_header(self):
        """Print ethical framework header"""
        ethical_principles = [
            "🤝 RESPECT: Treat all members with dignity",
            "🔒 PRIVACY: Consent-based interactions only", 
            "🌱 CONSTRUCTIVE: Foster positive dialogue",
            "⚖️ TRANSPARENT: Open moderation actions",
            "🛡️ SECURE: End-to-end encrypted"
        ]
        
        print(f"\n{self.colors['ethical']}{'='*70}")
        print("           ETHICAL LAN MESSENGER - COMMUNITY COVENANT")
        print('='*70)
        for principle in ethical_principles:
            print(f"   {principle}")
        print(f"{'='*70}{self.colors['reset']}\n")
    
    def print_animated_header(self, text):
        print(f"\n{self.colors['system']}{'='*60}")
        self.animate_text(text, speed=0.1)
        print(f"{'='*60}{self.colors['reset']}\n")
    
    def animate_text(self, text, speed=0.1, frames=20):
        for i, char in enumerate(text):
            print(char, end='', flush=True)
            if i < len(text) - 1:
                time.sleep(speed)
        print()
    
    def spinning_animation(self, duration=2, message="Processing"):
        end_time = time.time() + duration
        while time.time() < end_time:
            frame = self.animation_frames[self.current_frame]
            print(f"\r{self.colors['system']}{message} {frame}{self.colors['reset']}", end='', flush=True)
            self.current_frame = (self.current_frame + 1) % len(self.animation_frames)
            time.sleep(0.1)
        print("\r" + " " * (len(message) + 2) + "\r", end='', flush=True)
    
    def colorize_username(self, username):
        color_index = hash(username) % 6
        colors = [Fore.RED, Fore.GREEN, Fore.YELLOW, Fore.BLUE, Fore.MAGENTA, Fore.CYAN]
        return colors[color_index] + Style.BRIGHT + username + self.colors['reset']
    
    def print_message(self, username, message, is_own_message=False):
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        if is_own_message:
            user_display = f"{self.colors['user']}You{self.colors['reset']}"
        else:
            user_display = self.colorize_username(username)
        
        message_display = f"{self.colors['timestamp']}[{timestamp}]{self.colors['reset']} {user_display}: {message}"
        self.animate_text(message_display, speed=0.01)
    
    def print_ethical_warning(self, level, message):
        """Print ethical warning messages"""
        icons = {'low': '💡', 'medium': '⚠️', 'high': '🚫'}
        color = {'low': Fore.BLUE, 'medium': Fore.YELLOW, 'high': Fore.RED}
        
        warning_msg = f"{icons[level]} {color[level]}{message}{self.colors['reset']}"
        self.animate_text(warning_msg, speed=0.03)
    
    def print_moderation_action(self, action, username, details):
        """Print moderation action transparently"""
        mod_msg = f"{self.colors['moderation']}🛡️ {action} for {username}: {details}{self.colors['reset']}"
        self.animate_text(mod_msg, speed=0.03)
    
    def print_error(self, message):
        """Print error message with animation"""
        error_msg = f"⚠️  {self.colors['error']}{message}{self.colors['reset']}"
        self.animate_text(error_msg, speed=0.03)
    
    def print_success(self, message):
        """Print success message with animation"""
        success_msg = f"✅ {self.colors['success']}{message}{self.colors['reset']}"
        self.animate_text(success_msg, speed=0.03)
    
    def print_warning(self, message):
        """Print warning message"""
        warning_msg = f"⚠️  {self.colors['warning']}{message}{self.colors['reset']}"
        self.animate_text(warning_msg, speed=0.03)

class EthicalLANMessenger:
    def __init__(self, username=None, port=8888, password=None):
        self.port = port
        self.username = username or socket.gethostname()
        self.running = False
        self.socket = None
        self.connected_users = set()
        
        # Ethical framework components
        self.ethical_filter = EthicalFilter()
        self.transparency_logger = TransparencyLogger()
        self.community_governance = CommunityGovernance()
        self.deescalation_bot = DeescalationBot()
        
        # Security setup
        if not password:
            password = getpass.getpass("Enter chat room password: ")
        self.security = SecurityManager(password)
        self.rate_limiter = RateLimiter(max_messages=15, time_window=60)
        
        # Display setup
        self.display = AnimatedDisplay()
        
        # User management
        self.authenticated_users = {}
        self.user_contact_lists = defaultdict(set)  # Consent-based messaging
        self.opt_out_private_messages = set()
        
        print(f"\n{self.display.colors['system']}Initializing ethical messenger...{self.display.colors['reset']}")
        self.display.spinning_animation(2, "Loading ethical framework")
    
    def _get_user_consent(self):
        """Get user consent for ethical framework"""
        self.display.print_ethical_header()
        
        consent_text = """
By using Ethical LAN Messenger, you agree to:
1. Treat all participants with respect and dignity
2. Accept transparent moderation of content
3. Respect others' privacy and consent preferences
4. Participate in constructive community governance
5. Accept responsibility for your communications

Do you accept these terms? (yes/no): """
        
        response = input(f"{self.display.colors['system']}{consent_text}{self.display.colors['reset']}").strip().lower()
        
        if response not in ['yes', 'y']:
            self.display.print_error("Cannot proceed without accepting ethical framework.")
            sys.exit(1)
        
        # Set privacy preferences
        privacy_opt = input(f"{self.display.colors['system']}Allow private messages from non-contacts? (yes/no): {self.display.colors['reset']}").strip().lower()
        if privacy_opt in ['no', 'n']:
            self.opt_out_private_messages.add(self.username)

    def stop(self):
        """Stop the ethical messenger service"""
        self.running = False
        if self.socket:
            self.socket.close()
        self.display.print_success("Ethical messenger stopped securely. Goodbye!")
    
    def _broadcast_presence(self):
        """Broadcast secure user presence to the network"""
        if not self.rate_limiter.check_limit(self.username):
            self.display.print_error("Rate limit exceeded for presence broadcast")
            return
            
        message = {
            'type': 'presence',
            'username': self.username,
            'hostname': socket.gethostname(),
            'auth_timestamp': time.time()
        }
        
        try:
            encrypted_message = self.security.encrypt_message(message)
            self._send_broadcast(encrypted_message)
            self.rate_limiter.record_message(self.username)
        except SecurityError as e:
            self.display.print_error(f"Security error in presence broadcast: {e}")
    
    def _send_broadcast(self, data):
        """Broadcast encrypted data to the LAN"""
        try:
            json_data = json.dumps(data).encode('utf-8')
            # Broadcast to all devices in the network
            self.socket.sendto(json_data, ('<broadcast>', self.port))
        except Exception as e:
            self.display.print_error(f"Network error sending message: {e}")
    
    def _listen_for_messages(self):
        """Listen for incoming encrypted messages"""
        while self.running:
            try:
                data, addr = self.socket.recvfrom(4096)
                if not data:
                    continue
                
                try:
                    message = json.loads(data.decode('utf-8'))
                    self._handle_secure_message(message, addr)
                    
                except json.JSONDecodeError:
                    continue  # Ignore malformed JSON
                except SecurityError as e:
                    self.display.print_error(f"Security violation from {addr[0]}: {e}")
                    continue
                
            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    self.display.print_error(f"Network error receiving message: {e}")
    
    def _handle_secure_message(self, encrypted_message, addr):
        """Handle incoming encrypted messages with ethical security checks"""
        try:
            # Decrypt and verify message
            message = self.security.decrypt_message(encrypted_message)
            msg_type = message.get('type')
            
            # Additional rate limiting check
            sender_username = message.get('username')
            if not self.rate_limiter.check_limit(sender_username):
                return  # Silently drop rate-limited messages
            
            if msg_type == 'presence':
                username = message.get('username')
                if username != self.username:  # Don't show our own presence
                    self.connected_users.add(username)
                    self.authenticated_users[username] = time.time()
                    self.display.print_success(f"{self.display.colorize_username(username)} joined the secure chat")
            
            elif msg_type == 'message':
                username = message.get('username')
                text = message.get('text')
                
                if username != self.username:  # Don't show our own messages
                    # Apply ethical filtering to incoming messages
                    severity, violations = self.ethical_filter.scan_message(text, username)
                    
                    if severity == 'high':
                        self.transparency_logger.log_action(
                            'FILTERED_INCOMING_MESSAGE', 
                            username, 
                            f"Blocked ethical violation: {violations}"
                        )
                        return  # Don't display blocked messages
                    
                    self.rate_limiter.record_message(username)
                    self.display.print_message(username, text, is_own_message=False)
                    
                    # Check for conversation heat from other users
                    if self.deescalation_bot.analyze_conversation_heat(username, text):
                        deescalation_msg = self.deescalation_bot.get_deescalation_message()
                        self.display.print_ethical_warning('medium', deescalation_msg)
                    
        except SecurityError as e:
            self.display.print_error(f"Security error processing message from {addr[0]}: {e}")
    
    def _check_message_ethics(self, text):
        """Check message against ethical guidelines"""
        if self.ethical_filter.check_user_status(self.username):
            self.display.print_ethical_warning('high', "Your account is temporarily restricted due to guideline violations.")
            return False, 'blocked'
        
        severity, violations = self.ethical_filter.scan_message(text, self.username)
        
        if severity == 'high':
            self.transparency_logger.log_action(
                'BLOCKED_MESSAGE', 
                self.username, 
                f"Ethical violation: {violations}"
            )
            return False, 'blocked'
        elif severity == 'medium':
            self.display.print_ethical_warning('medium', 
                self.ethical_filter.get_warning_message('medium'))
            return True, 'warning'
        
        return True, 'clean'
    
    def _send_message(self, text):
        """Send message with ethical checking"""
        # Check ethical guidelines
        is_allowed, status = self._check_message_ethics(text)
        
        if not is_allowed:
            return False
        
        if status == 'blocked':
            return False
        
        # Check rate limiting
        if not self.rate_limiter.check_limit(self.username):
            self.display.print_error("Rate limit exceeded. Please wait before sending more messages.")
            return False
        
        # Check for conversation heat
        if self.deescalation_bot.analyze_conversation_heat(self.username, text):
            deescalation_msg = self.deescalation_bot.get_deescalation_message()
            self.display.print_ethical_warning('medium', deescalation_msg)
        
        # Proceed with sending
        message = {
            'type': 'message',
            'username': self.username,
            'text': text,
            'auth_timestamp': time.time(),
            'ethical_status': status
        }
        
        try:
            encrypted_message = self.security.encrypt_message(message)
            self._send_broadcast(encrypted_message)
            self.rate_limiter.record_message(self.username)
            
            # Display locally
            self.display.print_message(self.username, text, is_own_message=True)
            return True
            
        except SecurityError as e:
            self.display.print_error(f"Security error sending message: {e}")
            return False
    
    def _handle_private_message(self, target_user, message):
        """Handle consent-based private messaging"""
        if target_user in self.opt_out_private_messages:
            self.display.print_error(f"{target_user} has opted out of private messages.")
            return False
        
        if not self.community_governance.can_send_private_message(
            self.username, target_user, self.user_contact_lists):
            self.display.print_error(f"Cannot send private message. {target_user} is not in your contacts.")
            return False
        
        # Implementation for private messaging would go here
        self.display.print_success(f"Private message to {target_user}: {message}")
        return True
    
    def _handle_user_report(self, reported_user, reason, message_content):
        """Handle user reporting system"""
        self.community_governance.add_report(
            self.username, reported_user, reason, message_content
        )
        self.transparency_logger.log_action(
            'USER_REPORT',
            reported_user,
            f"Reported by {self.username}: {reason}",
            moderator="Community"
        )
        self.display.print_success(f"Report submitted against {reported_user}. Community moderators will review.")
    
    def _input_loop(self):
        """Handle user input with ethical command support"""
        while self.running:
            try:
                # Custom prompt with animation
                prompt = f"{self.display.colors['system']}💬 {self.display.colors['reset']}"
                text = input(prompt).strip()
                
                if text.lower() in ('quit', 'exit', 'q'):
                    break
                elif text.lower() == 'users':
                    self._show_connected_users()
                elif text.lower() == 'clear':
                    os.system('cls' if os.name == 'nt' else 'clear')
                elif text.lower() == 'status':
                    self._show_status()
                elif text.startswith('/'):
                    self._handle_command(text[1:])
                elif text:
                    # Show sending animation
                    self.display.spinning_animation(0.5, "Sending securely")
                    if not self._send_message(text):
                        self.display.print_error("Message failed to send")
                        
            except KeyboardInterrupt:
                break
            except EOFError:
                break
            except Exception as e:
                self.display.print_error(f"Input error: {e}")
    
    def _show_connected_users(self):
        """Show currently connected users with animations"""
        if not self.connected_users:
            self.display.print_warning("No other users connected")
            return
            
        self.display.print_success("Connected Users:")
        for user in self.connected_users:
            status = "🟢" if time.time() - self.authenticated_users.get(user, 0) < 60 else "🟡"
            print(f"  {status} {self.display.colorize_username(user)}")
    
    def _show_status(self):
        """Show system status with ethical information"""
        self.display.print_success("Ethical System Status:")
        print(f"  {self.display.colors['system']}• Users online: {len(self.connected_users) + 1}")
        print(f"  {self.display.colors['system']}• Security: 🔒 End-to-End Encrypted")
        print(f"  {self.display.colors['system']}• Ethical Filter: 🛡️ Active")
        print(f"  {self.display.colors['system']}• Transparency: 📜 Moderation Logging")
        print(f"  {self.display.colors['system']}• Rate Limit: {self.rate_limiter.max_messages} messages/minute")
        print(f"  {self.display.colors['system']}• Your Warnings: {self.ethical_filter.user_warnings.get(self.username, 0)}/{self.ethical_filter.max_warnings}")
        print(f"  {self.display.colors['system']}• Privacy: {'🔒 Restricted' if self.username in self.opt_out_private_messages else '🌐 Open'}")
        print(f"  {self.display.colors['system']}• Uptime: {time.strftime('%H:%M:%S')}{self.display.colors['reset']}")
    
    def _show_ethical_help(self):
        """Show ethical command help"""
        self.display.print_animated_header("ETHICAL COMMANDS")
        ethical_commands = [
            ("/help", "Show ethical commands"),
            ("/users", "Show connected users"),
            ("/status", "Show system and ethical status"),
            ("/report <user> <reason>", "Report a user for guideline violation"),
            ("/contacts", "Manage your contact list"),
            ("/modlog", "Show recent moderation actions"),
            ("/privacy <on/off>", "Toggle private message settings"),
            ("/covenant", "Show community covenant")
        ]
        
        for cmd, desc in ethical_commands:
            print(f"  {self.display.colors['system']}{cmd:25}{self.display.colors['reset']} {desc}")
    
    def _handle_command(self, command):
        """Handle ethical commands"""
        cmd_parts = command.lower().split()
        if not cmd_parts:
            return
            
        if cmd_parts[0] == 'help':
            self._show_ethical_help()
        elif cmd_parts[0] == 'report' and len(cmd_parts) >= 3:
            reported_user = cmd_parts[1]
            reason = ' '.join(cmd_parts[2:])
            self._handle_user_report(reported_user, reason, "Manual report")
        elif cmd_parts[0] == 'modlog':
            self._show_moderation_log()
        elif cmd_parts[0] == 'covenant':
            self.display.print_ethical_header()
        elif cmd_parts[0] == 'privacy' and len(cmd_parts) >= 2:
            self._handle_privacy_setting(cmd_parts[1])
        else:
            self.display.print_error(f"Unknown ethical command: {command}")
    
    def _show_moderation_log(self):
        """Show transparent moderation log"""
        logs = self.transparency_logger.get_recent_logs(10)
        self.display.print_animated_header("TRANSPARENT MODERATION LOG")
        
        if not logs:
            self.display.print_success("No recent moderation actions")
            return
            
        for log in logs:
            print(f"{self.display.colors['timestamp']}[{log['timestamp']}]{self.display.colors['reset']} "
                  f"{self.display.colors['moderation']}{log['moderator']} {log['action']} "
                  f"for {log['user']}: {log['details']}{self.display.colors['reset']}")
    
    def _handle_privacy_setting(self, setting):
        """Handle privacy preference changes"""
        if setting in ['off', 'no', 'disable']:
            self.opt_out_private_messages.add(self.username)
            self.display.print_success("Private messages from non-contacts disabled")
        elif setting in ['on', 'yes', 'enable']:
            self.opt_out_private_messages.discard(self.username)
            self.display.print_success("Private messages from non-contacts enabled")
        else:
            self.display.print_error("Invalid privacy setting. Use 'on' or 'off'")
    
    def _show_rate_limit(self):
        """Show current rate limit status"""
        remaining = self.rate_limiter.max_messages - len(self.rate_limiter.message_times)
        self.display.print_success(f"Rate Limit: {remaining}/{self.rate_limiter.max_messages} messages remaining")

    def start(self):
        """Start the ethical messenger service"""
        try:
            # Get user consent first
            self._get_user_consent()
            
            # Create UDP socket
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.settimeout(0.1)
            
            self.socket.bind(('', self.port))
            self.running = True
            
            self.display.print_animated_header("ETHICAL LAN MESSENGER ACTIVE")
            print(f"{self.display.colors['success']}🔒 End-to-End Encrypted Connection{self.display.colors['reset']}")
            print(f"{self.display.colors['success']}🤝 Ethical Framework Active{self.display.colors['reset']}")
            print(f"{self.display.colors['success']}🛡️  Transparent Moderation Enabled{self.display.colors['reset']}")
            print(f"{self.display.colors['system']}👤 Username: {self.username}")
            print(f"{self.display.colors['system']}🌐 Port: {self.port}")
            print(f"{self.display.colors['system']}💬 Type '/help' for ethical commands{self.display.colors['reset']}")
            print(f"{self.display.colors['timestamp']}{'-'*60}{self.display.colors['reset']}")
            
            # Start listening thread
            listen_thread = threading.Thread(target=self._listen_for_messages)
            listen_thread.daemon = True
            listen_thread.start()
            
            # Broadcast ethical presence
            self._broadcast_presence()
            
            # Start input loop
            self._input_loop()
            
        except Exception as e:
            self.display.print_error(f"Error starting messenger: {e}")
        finally:
            self.stop()

def main():
    """Main function with ethical setup"""
    try:
        display = AnimatedDisplay()
        display.print_animated_header("ETHICAL LAN MESSENGER")
        
        print(f"{display.colors['system']}Please choose your username:{display.colors['reset']}")
        
        while True:
            username = input(f"{display.colors['system']}👤 Username: {display.colors['reset']}").strip()
            if username:
                break
            display.print_error("Username cannot be empty")
        
        # Create and start ethical messenger
        messenger = EthicalLANMessenger(username=username)
        
        try:
            messenger.start()
        except KeyboardInterrupt:
            print(f"\n{messenger.display.colors['system']}Shutting down ethical messenger...{messenger.display.colors['reset']}")
        finally:
            messenger.stop()
            
    except Exception as e:
        print(f"\n{Fore.RED}Critical error: {e}{Style.RESET_ALL}")
        sys.exit(1)

if __name__ == "__main__":
    main()