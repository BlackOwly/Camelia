"""Camellia App — GUI и интеграция (Участник 3)."""

import os
import secrets
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

import camellia_engine as engine
from camellia_core import generate_subkeys

KEY_SIZES = {"128 бит": 16, "192 бита": 24, "256 бит": 32}
ENC_EXT = ".cam"


# ---------------------------------------------------------------- логика
def parse_key(text: str) -> bytes:
    """Превращает hex-строку в ключ и проверяет его длину."""
    s = "".join(text.split())
    if not s:
        raise ValueError("Введите ключ.")
    try:
        key = bytes.fromhex(s)
    except ValueError:
        raise ValueError("Ключ должен содержать только символы 0-9 и a-f.")
    if len(key) not in (16, 24, 32):
        raise ValueError(
            f"Неверная длина ключа: {len(s)} hex-символов. "
            "Нужно 32 (128 бит), 48 (192 бита) или 64 (256 бит)."
        )
    generate_subkeys(key)  # ValueError, если ядро ключ не принимает
    return key


def default_output(path: str, encrypt: bool) -> str:
    if encrypt:
        return path + ENC_EXT
    if path.endswith(ENC_EXT):
        return path[: -len(ENC_EXT)]
    return path + ".dec"


def _run_encrypt(src: str, dst: str, key: bytes) -> None:
    engine.encrypt_file(src, dst, key)


def _run_decrypt(src: str, dst: str, key: bytes) -> None:
    engine.decrypt_file(src, dst, key)


# ------------------------------------------------------------------- GUI
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Camellia — шифрование файлов (RFC 3713)")
        self.resizable(False, False)

        self.src = tk.StringVar()
        self.dst = tk.StringVar()
        self.key_hex = tk.StringVar()
        self.key_size = tk.StringVar(value="128 бит")
        self.mode = tk.StringVar(value="encrypt")
        self.status = tk.StringVar(value="Выберите файл и введите ключ.")

        pad = {"padx": 8, "pady": 4}
        frm = ttk.Frame(self, padding=10)
        frm.grid()

        ttk.Label(frm, text="Файл:").grid(row=0, column=0, sticky="w", **pad)
        ttk.Entry(frm, textvariable=self.src, width=50).grid(row=0, column=1, **pad)
        ttk.Button(frm, text="Обзор…", command=self.pick_src).grid(row=0, column=2, **pad)

        ttk.Label(frm, text="Сохранить как:").grid(row=1, column=0, sticky="w", **pad)
        ttk.Entry(frm, textvariable=self.dst, width=50).grid(row=1, column=1, **pad)
        ttk.Button(frm, text="Обзор…", command=self.pick_dst).grid(row=1, column=2, **pad)

        ttk.Label(frm, text="Длина ключа:").grid(row=2, column=0, sticky="w", **pad)
        ttk.Combobox(
            frm, textvariable=self.key_size, values=list(KEY_SIZES),
            state="readonly", width=10,
        ).grid(row=2, column=1, sticky="w", **pad)

        ttk.Label(frm, text="Ключ (hex):").grid(row=3, column=0, sticky="w", **pad)
        ttk.Entry(frm, textvariable=self.key_hex, width=50).grid(row=3, column=1, **pad)
        ttk.Button(frm, text="Создать", command=self.gen_key).grid(row=3, column=2, **pad)

        modes = ttk.Frame(frm)
        modes.grid(row=4, column=1, sticky="w", **pad)
        ttk.Radiobutton(modes, text="Зашифровать", variable=self.mode,
                        value="encrypt", command=self.update_dst).pack(side="left")
        ttk.Radiobutton(modes, text="Расшифровать", variable=self.mode,
                        value="decrypt", command=self.update_dst).pack(side="left", padx=12)

        self.btn = ttk.Button(frm, text="Выполнить", command=self.start)
        self.btn.grid(row=5, column=1, sticky="w", **pad)

        self.bar = ttk.Progressbar(frm, mode="indeterminate", length=380)
        self.bar.grid(row=6, column=0, columnspan=3, **pad)
        ttk.Label(frm, textvariable=self.status, wraplength=480).grid(
            row=7, column=0, columnspan=3, sticky="w", **pad)

    # --- выбор файлов
    def pick_src(self):
        path = filedialog.askopenfilename(title="Выберите файл")
        if path:
            self.src.set(path)
            if path.endswith(ENC_EXT):
                self.mode.set("decrypt")
            self.update_dst()

    def pick_dst(self):
        path = filedialog.asksaveasfilename(title="Куда сохранить")
        if path:
            self.dst.set(path)

    def update_dst(self):
        if self.src.get():
            self.dst.set(default_output(self.src.get(), self.mode.get() == "encrypt"))

    def gen_key(self):
        n = KEY_SIZES[self.key_size.get()]
        self.key_hex.set(secrets.token_bytes(n).hex())
        self.status.set("Ключ создан. Сохраните его: без него файл не расшифровать.")

    # --- запуск операции
    def start(self):
        src, dst = self.src.get().strip(), self.dst.get().strip()
        if not src or not os.path.isfile(src):
            return messagebox.showerror("Ошибка", "Выберите существующий файл.")
        if not dst:
            return messagebox.showerror("Ошибка", "Укажите, куда сохранить результат.")
        if os.path.abspath(src) == os.path.abspath(dst):
            return messagebox.showerror("Ошибка", "Исходный и выходной файлы совпадают.")
        try:
            key = parse_key(self.key_hex.get())
        except ValueError as e:
            return messagebox.showerror("Неверный ключ", str(e))
        if os.path.exists(dst) and not messagebox.askyesno(
                "Файл существует", "Перезаписать выходной файл?"):
            return

        run = _run_encrypt if self.mode.get() == "encrypt" else _run_decrypt
        self.btn.state(["disabled"])
        self.bar.start(12)
        self.status.set("Работаю…")
        threading.Thread(target=self._worker, args=(run, src, dst, key),
                         daemon=True).start()

    def _worker(self, run, src, dst, key):
        try:
            run(src, dst, key)
            self.after(0, self._done, f"Готово: {dst}", None)
        except Exception as e:  # ошибки движка показываем пользователю
            if os.path.exists(dst):
                try:
                    os.remove(dst)  # не оставляем битый файл
                except OSError:
                    pass
            self.after(0, self._done, None, e)

    def _done(self, ok_msg, err):
        self.bar.stop()
        self.btn.state(["!disabled"])
        if err is None:
            self.status.set(ok_msg)
            messagebox.showinfo("Успех", ok_msg)
        else:
            self.status.set(f"Ошибка: {err}")
            messagebox.showerror(
                "Ошибка",
                f"Не удалось выполнить операцию:\n{err}\n\n"
                "Проверьте ключ и что файл был зашифрован этим приложением.")


if __name__ == "__main__":
    App().mainloop()
  
