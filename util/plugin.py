__ALL__ = ['load_class']

def load_class(name):
    path = name.split('.')
    cls = None
    try:
        mod = __import__('.'.join(path[:-1]))
        for attr in path[1:]:
            if hasattr(mod, attr):
                mod = getattr(mod, attr)
                cls = mod
            else:
                cls = None
                break
    except ImportError:
        pass

    return (name, cls)
