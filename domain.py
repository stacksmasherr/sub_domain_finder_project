import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk
import dns.resolver
import threading
import queue
import time

# Define color scheme
BACKGROUND_COLOR = "#f4f4f9"
PRIMARY_COLOR = "#4a90e2"
SECONDARY_COLOR = "#007aff"
TEXT_COLOR = "#333333"
BUTTON_COLOR = "#4a90e2"
BUTTON_HOVER_COLOR = "#357abd"

# Apply styling
def apply_styles(widget):
    widget.configure(bg=BACKGROUND_COLOR, fg=TEXT_COLOR, font=("Arial", 12))

def apply_button_styles(button):
    button.configure(bg=BUTTON_COLOR, fg="white", font=("Arial", 12, "bold"))
    button.bind("<Enter>", lambda e: button.configure(bg=BUTTON_HOVER_COLOR))
    button.bind("<Leave>", lambda e: button.configure(bg=BUTTON_COLOR))

# Global variables
cancel_event = threading.Event()
threads = []
scan_thread = None

def resolve_subdomain(domain, subdomain, record_type='A'):
    full_domain = f"{subdomain}.{domain}"
    retries = 3
    for attempt in range(retries):
        if cancel_event.is_set():
            return None
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 5  # Set timeout to 5 seconds
            resolver.lifetime = 15  # Overall lifetime for resolution
            resolver.nameservers = ['1.1.1.1', '1.0.0.1']  # Cloudflare DNS servers
            answers = resolver.resolve(full_domain, record_type)
            return full_domain
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.name.EmptyLabel):
            return None
        except dns.exception.Timeout:
            print(f"Attempt {attempt+1}: Timeout resolving {full_domain}. Retrying...")
            time.sleep(2 ** attempt)  # Exponential backoff
        except Exception as e:
            print(f"Attempt {attempt+1}: Error resolving {full_domain}: {e}")
            return None
    print(f"All attempts failed for {full_domain}.")
    return None

def process_subdomains(subdomains, domain, record_type, progress_queue):
    found_subdomains = []
    total = len(subdomains)
    for idx, subdomain in enumerate(subdomains):
        if cancel_event.is_set():
            break
        subdomain = subdomain.strip()
        if not subdomain:
            continue
        result = resolve_subdomain(domain, subdomain, record_type)
        if result:
            found_subdomains.append(result)
        progress_queue.put((idx + 1, total))  # Update progress
        time.sleep(0.1)  # Add a small delay between queries to avoid rate limiting
    return found_subdomains

def find_subdomains(domain, wordlist, record_type, progress_queue, num_threads):
    found_subdomains = []
    try:
        with open(wordlist, 'r') as file:
            subdomains = file.readlines()
        
        total = len(subdomains)
        chunk_size = (total // num_threads) + 1
        subdomain_chunks = [subdomains[i:i + chunk_size] for i in range(0, total, chunk_size)]

        def worker(chunk):
            nonlocal found_subdomains
            results = process_subdomains(chunk, domain, record_type, progress_queue)
            found_subdomains.extend(results)
        
        threads.clear()
        for chunk in subdomain_chunks:
            if cancel_event.is_set():
                break
            thread = threading.Thread(target=worker, args=(chunk,), daemon=True)
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()
        
    except Exception as e:
        messagebox.showerror("Error", f"Failed to read wordlist or process subdomains: {e}")
    
    progress_queue.put((None, None))  # Signal completion
    return found_subdomains

def start_scan():
    global scan_thread
    domain = domain_entry.get().strip()
    wordlist = wordlist_entry.get().strip()
    record_type = record_type_var.get()
    try:
        num_threads = int(threads_entry.get().strip())
    except ValueError:
        messagebox.showwarning("Input Error", "Please enter a valid number of threads.")
        return

    if not domain or not wordlist:
        messagebox.showwarning("Input Error", "Please enter both domain and wordlist file path.")
        return

    domain = domain.replace("http://", "").replace("https://", "")  # Clean domain input

    result_text.delete(1.0, tk.END)
    progress_bar['value'] = 0
    progress_label.config(text="Starting scan...")
    window.update()

    # Create a queue to communicate progress updates from the thread
    progress_queue = queue.Queue()
    
    # Reset cancellation event
    cancel_event.clear()

    def scan_thread_func():
        try:
            subdomains = find_subdomains(domain, wordlist, record_type, progress_queue, num_threads)
            display_results(subdomains)
        except Exception as e:
            print(f"Scan thread error: {e}")
        finally:
            cancel_event.set()  # Ensure cancellation event is set on completion

    # Start the scanning process in a separate thread
    scan_thread = threading.Thread(target=scan_thread_func, daemon=True)
    scan_thread.start()

    # Poll the progress queue and update the GUI
    def check_progress():
        try:
            while True:
                completed, total = progress_queue.get_nowait()
                if completed is None and total is None:
                    break
                if total > 0:
                    progress = (completed / total) * 100
                    progress_bar['value'] = progress
                    progress_label.config(text=f"Progress: {completed}/{total}")
                window.update_idletasks()
        except queue.Empty:
            window.after(100, check_progress)  # Check progress again after 100ms

    check_progress()

def cancel_scan():
    cancel_event.set()
    if scan_thread and scan_thread.is_alive():
        try:
            scan_thread.join(timeout=5)  # Wait for the thread to finish with timeout
        except Exception as e:
            print(f"Error joining scan thread: {e}")
    if not window.winfo_exists():
        return
    try:
        messagebox.showinfo("Cancelled", "Scan has been cancelled.")
    except Exception as e:
        print(f"Error showing cancellation message: {e}")

def display_results(subdomains):
    result_text.delete(1.0, tk.END)
    
    if subdomains:
        result_text.insert(tk.END, "Found subdomains:\n")
        for subdomain in subdomains:
            result_text.insert(tk.END, f"{subdomain}\n")
    else:
        result_text.insert(tk.END, "No subdomains found.")

def browse_wordlist():
    filepath = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
    if filepath:
        wordlist_entry.delete(0, tk.END)
        wordlist_entry.insert(0, filepath)

def export_results():
    filepath = filedialog.asksaveasfilename(defaultextension=".txt",
                                           filetypes=[("Text files", "*.txt")])
    if filepath:
        with open(filepath, 'w') as file:
            file.write(result_text.get(1.0, tk.END))
        messagebox.showinfo("Export", "Results exported successfully!")

# Set up the main application window
window = tk.Tk()
window.title("Advanced Subdomain Finder")
window.configure(bg=BACKGROUND_COLOR)

# Domain input
tk.Label(window, text="Domain:", bg=BACKGROUND_COLOR).grid(row=0, column=0, padx=10, pady=10, sticky="e")
domain_entry = tk.Entry(window, width=50)
domain_entry.grid(row=0, column=1, padx=10, pady=10)
apply_styles(domain_entry)

# Wordlist input
tk.Label(window, text="Wordlist File:", bg=BACKGROUND_COLOR).grid(row=1, column=0, padx=10, pady=10, sticky="e")
wordlist_entry = tk.Entry(window, width=50)
wordlist_entry.grid(row=1, column=1, padx=10, pady=10)
apply_styles(wordlist_entry)
tk.Button(window, text="Browse", command=browse_wordlist).grid(row=1, column=2, padx=10, pady=10)

# Record type input
tk.Label(window, text="DNS Record Type:", bg=BACKGROUND_COLOR).grid(row=2, column=0, padx=10, pady=10, sticky="e")
record_type_var = tk.StringVar(value='A')
record_types = ['A', 'AAAA', 'CNAME', 'MX']
for i, record_type in enumerate(record_types):
    tk.Radiobutton(window, text=record_type, variable=record_type_var, value=record_type, bg=BACKGROUND_COLOR).grid(row=2, column=i+1, padx=10, pady=10)

# Number of threads input
tk.Label(window, text="Number of Threads:", bg=BACKGROUND_COLOR).grid(row=3, column=0, padx=10, pady=10, sticky="e")
threads_entry = tk.Entry(window, width=5)
threads_entry.grid(row=3, column=1, padx=10, pady=10)
threads_entry.insert(0, '10')  # Default to 10 threads
apply_styles(threads_entry)

# Start scan button
start_button = tk.Button(window, text="Start Scan", command=start_scan)
start_button.grid(row=4, column=0, padx=10, pady=10)
apply_button_styles(start_button)

# Cancel scan button
cancel_button = tk.Button(window, text="Cancel Scan", command=cancel_scan)
cancel_button.grid(row=4, column=1, padx=10, pady=10)
apply_button_styles(cancel_button)

# Export results button
export_button = tk.Button(window, text="Export Results", command=export_results)
export_button.grid(row=4, column=2, padx=10, pady=10)
apply_button_styles(export_button)

# Progress bar and label
progress_bar = ttk.Progressbar(window, length=400, mode='determinate')
progress_bar.grid(row=5, column=0, columnspan=3, padx=10, pady=10)
progress_label = tk.Label(window, text="Progress: 0/0", bg=BACKGROUND_COLOR)
progress_label.grid(row=6, column=0, columnspan=3, padx=10, pady=10)

# Results text area
result_text = scrolledtext.ScrolledText(window, width=80, height=20)
result_text.grid(row=7, column=0, columnspan=3, padx=10, pady=10)
apply_styles(result_text)

window.mainloop()