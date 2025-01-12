def export_to_txt(content, filename="crypto_output.txt"):
    with open(filename, "w") as file:
        file.write(content)
    print(f"Output saved to {filename}")
