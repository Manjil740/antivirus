import os
import hashlib
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from threading import Thread
from queue import Queue
import time

class MalwareScanner:
    def __init__(self):
        # Expanded list of known malicious hashes (MD5)
        # In a real application, these would come from a regularly updated database
        self.known_malware_hashes = {
            'd41d8cd98f00b204e9800998ecf8427e',  # Example empty file hash
            '098f6bcd4621d373cade4e832627b4f6',  # Example "test" hash
            '5d41402abc4b2a76b9719d911017c592',  # Example "hello" hash
            # Add more hashes as needed
        }
        
        # System files and directories to exclude
        self.excluded_items = {
            'hiberfil.sys', 'pagefile.sys', 'swapfile.sys',
            'DumpStack.log', 'DumpStack.log.tmp',
            '$RECYCLE.BIN', 'System Volume Information',
            'Windows', 'Program Files', 'Program Files (x86)'
        }
        
        # Supported hash algorithms
        self.supported_algorithms = {
            'md5': hashlib.md5,
            'sha1': hashlib.sha1,
            'sha256': hashlib.sha256
        }
        
        # Scan statistics
        self.scan_stats = {
            'files_scanned': 0,
            'malware_found': 0,
            'scan_time': 0,
            'total_size': 0
        }
        
        # Thread control
        self.scan_thread = None
        self.stop_scan = False
        self.message_queue = Queue()
        
        # Initialize UI
        self.setup_ui()
        
    def setup_ui(self):
        """Initialize the user interface"""
        self.root = tk.Tk()
        self.root.title("Enhanced Malware Scanner")
        self.root.geometry("700x600")
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        
        # Configure styles
        style = ttk.Style()
        style.configure('TButton', padding=5)
        style.configure('TProgressbar', thickness=20)
        
        # Main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Directory selection
        dir_frame = ttk.LabelFrame(main_frame, text="Scan Directory", padding="10")
        dir_frame.pack(fill=tk.X, pady=5)
        
        self.directory_entry = ttk.Entry(dir_frame, width=50)
        self.directory_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        
        ttk.Button(dir_frame, text="Browse", command=self.browse_directory).pack(side=tk.LEFT)
        
        # Options frame
        options_frame = ttk.LabelFrame(main_frame, text="Scan Options", padding="10")
        options_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(options_frame, text="Hash Algorithm:").pack(side=tk.LEFT)
        self.hash_algo = tk.StringVar(value='sha256')
        for algo in self.supported_algorithms:
            ttk.Radiobutton(
                options_frame, 
                text=algo.upper(), 
                variable=self.hash_algo, 
                value=algo
            ).pack(side=tk.LEFT, padx=5)
        
        # Control buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=10)
        
        self.scan_button = ttk.Button(
            button_frame, 
            text="Start Scan", 
            command=self.start_scan_threaded
        )
        self.scan_button.pack(side=tk.LEFT, padx=5)
        
        self.stop_button = ttk.Button(
            button_frame, 
            text="Stop Scan", 
            command=self.stop_scan_process,
            state=tk.DISABLED
        )
        self.stop_button.pack(side=tk.LEFT, padx=5)
        
        # Progress display
        progress_frame = ttk.LabelFrame(main_frame, text="Scan Progress", padding="10")
        progress_frame.pack(fill=tk.X, pady=5)
        
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(
            progress_frame, 
            length=300, 
            variable=self.progress_var, 
            maximum=100,
            mode='determinate'
        )
        self.progress_bar.pack(fill=tk.X, pady=5)
        
        self.progress_label = ttk.Label(
            progress_frame, 
            text="Ready to scan. Select a directory and click Start Scan."
        )
        self.progress_label.pack(fill=tk.X)
        
        self.stats_label = ttk.Label(
            progress_frame,
            text="Files scanned: 0 | Malware found: 0 | Scan time: 0s"
        )
        self.stats_label.pack(fill=tk.X)
        
        # Results display
        results_frame = ttk.LabelFrame(main_frame, text="Scan Results", padding="10")
        results_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        self.result_box = tk.Text(results_frame, wrap=tk.WORD)
        self.result_box.pack(fill=tk.BOTH, expand=True)
        
        scrollbar = ttk.Scrollbar(self.result_box)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.result_box.config(yscrollcommand=scrollbar.set)
        scrollbar.config(command=self.result_box.yview)
        
        # Status bar
        self.status_bar = ttk.Label(
            main_frame, 
            text="Ready", 
            relief=tk.SUNKEN,
            anchor=tk.W
        )
        self.status_bar.pack(fill=tk.X, pady=(5, 0))
        
        # Start the message pump
        self.root.after(100, self.process_messages)
    
    def browse_directory(self):
        """Open file dialog to browse and select directory"""
        directory = filedialog.askdirectory()
        if directory:
            self.directory_entry.delete(0, tk.END)
            self.directory_entry.insert(0, directory)
    
    def get_file_hash(self, file_path, hash_algo='sha256'):
        """Calculate the hash of a file using the specified algorithm"""
        if hash_algo not in self.supported_algorithms:
            self.message_queue.put(("error", f"Unsupported hash algorithm: {hash_algo}"))
            return None
        
        hash_func = self.supported_algorithms[hash_algo]()
        try:
            with open(file_path, 'rb') as f:
                while chunk := f.read(8192):  # Read in 8KB chunks
                    if self.stop_scan:
                        return None
                    hash_func.update(chunk)
            return hash_func.hexdigest()
        except PermissionError:
            self.message_queue.put(("warning", f"Permission denied: {file_path}"))
            return None
        except Exception as e:
            self.message_queue.put(("error", f"Error reading {file_path}: {str(e)}"))
            return None
    
    def should_skip(self, path):
        """Determine if a file/directory should be skipped during scanning"""
        name = os.path.basename(path)
        return (name.startswith('~$') or  # Temporary office files
                name.startswith('.') or   # Hidden files
                name in self.excluded_items)
    
    def count_files(self, directory):
        """Count total files to be scanned for progress reporting"""
        total = 0
        for root, dirs, files in os.walk(directory):
            # Skip excluded directories
            dirs[:] = [d for d in dirs if not self.should_skip(os.path.join(root, d))]
            
            # Count files that aren't excluded
            total += len([f for f in files if not self.should_skip(os.path.join(root, f))])
        return total
    
    def scan_directory(self, directory):
        """Scan all files in a given directory for known malware hashes"""
        start_time = time.time()
        total_files = self.count_files(directory)
        scanned_files = 0
        
        self.scan_stats = {
            'files_scanned': 0,
            'malware_found': 0,
            'scan_time': 0,
            'total_size': 0
        }
        
        if total_files == 0:
            self.message_queue.put(("info", "No files found to scan in the selected directory."))
            return []
        
        self.message_queue.put(("progress", (0, total_files)))
        self.message_queue.put(("status", f"Scanning {directory}..."))
        
        suspicious_files = []
        
        for root, dirs, files in os.walk(directory):
            if self.stop_scan:
                break
                
            # Skip excluded directories
            dirs[:] = [d for d in dirs if not self.should_skip(os.path.join(root, d))]
            
            for file in files:
                if self.stop_scan:
                    break
                    
                if self.should_skip(file):
                    continue
                    
                file_path = os.path.join(root, file)
                
                try:
                    file_size = os.path.getsize(file_path)
                    file_hash = self.get_file_hash(file_path, self.hash_algo.get())
                    
                    if file_hash is None:  # Skip if there was an error
                        continue
                        
                    scanned_files += 1
                    self.scan_stats['files_scanned'] = scanned_files
                    self.scan_stats['total_size'] += file_size
                    
                    # Update progress
                    if scanned_files % 10 == 0 or scanned_files == total_files:
                        progress = (scanned_files / total_files) * 100
                        self.message_queue.put(("progress", (scanned_files, total_files)))
                        self.message_queue.put(("stats", self.scan_stats))
                    
                    # Check against known hashes
                    if file_hash in self.known_malware_hashes:
                        self.scan_stats['malware_found'] += 1
                        suspicious_files.append(file_path)
                        self.message_queue.put(("alert", f"Malware detected: {file_path}"))
                
                except Exception as e:
                    self.message_queue.put(("error", f"Error processing {file_path}: {str(e)}"))
                    continue
        
        scan_time = time.time() - start_time
        self.scan_stats['scan_time'] = scan_time
        self.message_queue.put(("stats", self.scan_stats))
        
        if self.stop_scan:
            self.message_queue.put(("status", f"Scan stopped. Scanned {scanned_files} of {total_files} files."))
        else:
            self.message_queue.put(("status", f"Scan complete. Scanned {scanned_files} files in {scan_time:.2f} seconds."))
        
        return suspicious_files
    
    def start_scan_threaded(self):
        """Start the scan in a separate thread to keep the UI responsive"""
        directory = self.directory_entry.get().strip()
        
        if not directory:
            messagebox.showerror("Error", "Please specify a directory to scan.")
            return
        
        if not os.path.isdir(directory):
            messagebox.showerror("Error", f"The specified directory does not exist:\n{directory}")
            return
        
        # Reset UI elements
        self.result_box.delete(1.0, tk.END)
        self.progress_var.set(0)
        self.scan_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.stop_scan = False
        
        # Start the scan in a separate thread
        self.scan_thread = Thread(
            target=self.run_scan,
            args=(directory,),
            daemon=True
        )
        self.scan_thread.start()
    
    def run_scan(self, directory):
        """Wrapper function for the scan thread"""
        suspicious_files = self.scan_directory(directory)
        
        if not self.stop_scan:
            if suspicious_files:
                self.message_queue.put(("result", f"\nScan complete. Found {len(suspicious_files)} suspicious files."))
            else:
                self.message_queue.put(("result", "\nScan complete. No malware detected."))
        
        self.message_queue.put(("scan_complete", None))
    
    def stop_scan_process(self):
        """Stop the currently running scan"""
        self.stop_scan = True
        self.message_queue.put(("status", "Stopping scan..."))
        self.stop_button.config(state=tk.DISABLED)
    
    def process_messages(self):
        """Process messages from the scan thread to update the UI"""
        while not self.message_queue.empty():
            msg_type, content = self.message_queue.get()
            
            if msg_type == "progress":
                scanned, total = content
                progress = (scanned / total) * 100
                self.progress_var.set(progress)
                self.progress_label.config(
                    text=f"Scanning... {scanned}/{total} files ({progress:.1f}%)"
                )
            
            elif msg_type == "stats":
                stats = content
                self.stats_label.config(
                    text=f"Files scanned: {stats['files_scanned']} | "
                         f"Malware found: {stats['malware_found']} | "
                         f"Scan time: {stats['scan_time']:.1f}s | "
                         f"Data scanned: {stats['total_size']/1024/1024:.1f}MB"
                )
            
            elif msg_type == "alert":
                self.result_box.insert(tk.END, f"[!] {content}\n")
                self.result_box.see(tk.END)
            
            elif msg_type == "error":
                self.result_box.insert(tk.END, f"[ERROR] {content}\n", 'error')
                self.result_box.see(tk.END)
            
            elif msg_type == "warning":
                self.result_box.insert(tk.END, f"[Warning] {content}\n", 'warning')
                self.result_box.see(tk.END)
            
            elif msg_type == "info":
                self.result_box.insert(tk.END, f"[Info] {content}\n", 'info')
                self.result_box.see(tk.END)
            
            elif msg_type == "status":
                self.status_bar.config(text=content)
            
            elif msg_type == "result":
                self.result_box.insert(tk.END, content + "\n", 'result')
                self.result_box.see(tk.END)
            
            elif msg_type == "scan_complete":
                self.scan_button.config(state=tk.NORMAL)
                self.stop_button.config(state=tk.DISABLED)
        
        self.root.after(100, self.process_messages)
    
    def on_close(self):
        """Handle window close event"""
        if self.scan_thread and self.scan_thread.is_alive():
            if messagebox.askokcancel("Quit", "Scan is in progress. Are you sure you want to quit?"):
                self.stop_scan = True
                self.root.destroy()
        else:
            self.root.destroy()
    
    def run(self):
        """Run the application"""
        # Configure text tags for coloring
        self.result_box.tag_config('error', foreground='red')
        self.result_box.tag_config('warning', foreground='orange')
        self.result_box.tag_config('info', foreground='blue')
        self.result_box.tag_config('result', foreground='green')
        self.result_box.tag_config('alert', foreground='red', font=('TkDefaultFont', 10, 'bold'))
        
        self.root.mainloop()

if __name__ == "__main__":
    scanner = MalwareScanner()
    scanner.run()