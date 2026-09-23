import io, re
path = 'static/index.html'
with io.open(path, 'r', encoding='utf-8') as f:
    html = f.read()

# 1. Nuke any .modal rules that remain, insert a single clean one
html = re.sub(r'\.modal\s*\{[^}]*\}', '', html)
html = re.sub(r'\.modal-content\s*\{[^}]*\}', '', html)
html = re.sub(r'\.modal-content::before\s*\{[^}]*\}', '', html)
html = re.sub(r'@keyframes modalFadeIn\s*\{[^}]*\}[^@]*', '', html)
html = re.sub(r'@keyframes modalPopIn\s*\{[^}]*\}[^@]*', '', html)

# 2. Insert fresh, SOLID modal CSS right before </style>
fresh = """
/* ===== LOGIN MODAL - SOLID WHITE, LIGHT BACKDROP ===== */
.modal {
    display: flex;
    position: fixed;
    top: 0; left: 0;
    width: 100%; height: 100%;
    background: rgba(15, 23, 42, 0.45);
    backdrop-filter: blur(6px);
    -webkit-backdrop-filter: blur(6px);
    z-index: 2000;
    justify-content: center;
    align-items: center;
}
.modal-content {
    background: #ffffff;
    padding: 32px 28px;
    border-radius: 20px;
    width: 90%;
    max-width: 440px;
    max-height: 82vh;
    overflow-y: auto;
    box-shadow: 0 20px 50px rgba(0,0,0,0.35), 0 0 0 1px rgba(255,255,255,0.9) inset;
    border: 1px solid #e2e8f0;
    text-align: center;
}
.modal-content h2 {
    color: #1e3c72;
    margin-bottom: 20px;
    font-size: 1.5rem;
}
.modal-content input {
    width: 100%;
    padding: 12px;
    margin: 8px 0;
    border: 2px solid #cbd5e1;
    border-radius: 10px;
    font-size: 14px;
    background: #ffffff;
    color: #1e293b;
    text-align: left;
}
.modal-content input:focus {
    outline: none;
    border-color: #2563eb;
    box-shadow: 0 0 0 3px rgba(37, 99, 235, 0.15);
}
.modal-content button {
    width: 100%;
    padding: 12px;
    background: #2563eb;
    color: #ffffff;
    border: none;
    border-radius: 10px;
    font-weight: 600;
    cursor: pointer;
    font-size: 15px;
    margin-top: 6px;
}
.modal-content button:hover { background: #1d4ed8; }
.modal-content .switch-mode {
    text-align: center;
    margin-top: 14px;
    color: #2563eb;
    cursor: pointer;
    font-size: 14px;
}
.modal-content .error-msg {
    color: #dc2626;
    text-align: center;
    margin: 8px 0;
    font-size: 13px;
}
.modal-content .password-wrapper { position: relative; width: 100%; }
.modal-content .toggle-password {
    position: absolute;
    right: 12px;
    top: 50%;
    transform: translateY(-50%);
    cursor: pointer;
    color: #2563eb;
    background: transparent;
}
</style>"""

html = html.replace('</style>', fresh, 1)

with io.open(path, 'w', encoding='utf-8') as f:
    f.write(html)

# Verify
with io.open(path, 'r', encoding='utf-8') as f:
    t = f.read()
print('modal rules:', t.count('.modal {'))
print('modal-content rules:', t.count('.modal-content {'))
print('Lines:', len(t.splitlines()))
