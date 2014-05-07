'''
Created on Mar 25, 2014

@author: stefan
'''

from abc import ABCMeta, abstractmethod

class AbstractCipher(object):
    """
    """
    __metaclass__ = ABCMeta
    
    @abstractmethod
    def createSTP(self, filename, cipherParameters):
        pass
