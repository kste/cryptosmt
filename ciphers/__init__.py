import pkgutil
import importlib
from .cipher import AbstractCipher

# Fast mapping from module names to cipher names (where different)
_MODULE_TO_CIPHER = {
    "chaskeymachalf": "chaskeyhalf",
}

def get_cipher(name):
    """
    Efficiently gets a single cipher instance by name without importing everything.
    """
    # Check if we have a special mapping
    module_name = name
    for mod, ciph in _MODULE_TO_CIPHER.items():
        if ciph == name:
            module_name = mod
            break
            
    try:
        full_module_name = f"{__name__}.{module_name}"
        module = importlib.import_module(full_module_name)
        
        for attribute_name in dir(module):
            attribute = getattr(module, attribute_name)
            if (isinstance(attribute, type) and 
                issubclass(attribute, AbstractCipher) and 
                attribute is not AbstractCipher):
                
                cipher_instance = attribute()
                if cipher_instance.name == name:
                    return cipher_instance
    except (ImportError, SyntaxError):
        pass
        
    return None

def get_cipher_suite():
    """
    Dynamically discovers all available ciphers.
    """
    cipher_suite = {}
    for loader, module_name, is_pkg in pkgutil.walk_packages(__path__):
        if module_name == 'cipher':
            continue
            
        full_module_name = f"{__name__}.{module_name}"
        try:
            module = importlib.import_module(full_module_name)
            for attribute_name in dir(module):
                attribute = getattr(module, attribute_name)
                if (isinstance(attribute, type) and 
                    issubclass(attribute, AbstractCipher) and 
                    attribute is not AbstractCipher):
                    cipher_instance = attribute()
                    cipher_suite[cipher_instance.name] = cipher_instance
        except (ImportError, SyntaxError):
            continue
                
    return cipher_suite
