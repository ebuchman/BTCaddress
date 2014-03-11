import os

def check_vanity(pub, priv, target):
    file_name = os.path.join("data", target+".dat")

    if pub.lower().startswith("1" + target.lower()):
        f = open(file_name, "a")
        f.write("\n%s\n%s\n"%(priv, pub))
        f.close()
        return 1
    else:
        return 0
