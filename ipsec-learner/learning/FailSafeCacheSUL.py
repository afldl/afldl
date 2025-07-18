import constant
from colorama import Fore
from aalpy.base import SUL
from learning.CacheTree import CacheTree
from time import sleep
from learning.Errors import NonDeterministicError, RepeatedNonDeterministicError
from learning.FailSafeSUL import FailSafeSUL
from DBhelper import *
import logging
###
# The code used in this file is copied from the SweynTooth project:
# https://github.com/DES-Lab/AALpy
#
# Following file/class has been copied:
# -- aalpy/base/SUL.py
#
# Adaptions to the existing code have been made:
# -- check for non-determinism
#
#
###

logger = logging.getLogger('model learning')

class FailSafeCacheSUL(SUL):
    """
    System under learning that keeps a multiset of all queries in memory.
    This multiset/cache is encoded as a tree.
    """
    def __init__(self, sul: FailSafeSUL, database):
        super().__init__()
        self.sul = sul
        self.cache = CacheTree()
        self.non_det_query_counter = 0
        self.non_det_step_counter = 0
        self.dbhelper = DBhelper(database)

    def clean_cache(self):
        self.cache = CacheTree()
        
    def query(self, word):
        """
        Performs a membership query on the SUL if and only if `word` is not a prefix of any trace in the cache.
        Before the query, pre() method is called and after the query post()
        method is called. Each letter in the word (input in the input sequence) is executed using the step method.

        Args:

            word: membership query (word consisting of letters/inputs)

        Returns:

            list of outputs, where the i-th output corresponds to the output of the system after the i-th input

        """
        logging.info('*'*100)
        logging.info('current query : ' + str(word))
        
        results_in_db_str = self.dbhelper.execute_query(str(word))
        if results_in_db_str:
            logger.info(utils.logger_str('found in sqlite : ' + results_in_db_str))

            results_in_db = str2list(results_in_db_str)
            self.cache.reset()
            for i, o in zip(word, results_in_db):
                self.cache.step_in_cache(i, o)
            return results_in_db
        
        
        cached_query = self.cache.in_cache(word)
        if cached_query:
            logging.info('found in cache tree : ' + str(cached_query))
            self.num_cached_queries += 1
            return cached_query


        out = self.sul.query(word)
        # add input/outputs to tree
        self.cache.reset()
        for i, o in zip(word, out):
            self.cache.step_in_cache(i, o)

        self.dbhelper.insert_query(str(word), str(out))
        logger.info(utils.logger_str('insert to database'))
        return out






    def pre(self):
        """
        Reset the system under learning and current node in the cache tree.
        """
        self.cache.reset()
        self.sul.pre()

    def post(self):
        self.sul.post()

    def step(self, letter):
        """
        Executes an action on the system under learning, adds it to the cache and returns its result.

        Args:

           letter: Single input that is executed on the SUL.

        Returns:

           Output received after executing the input.

        """
        out = self.sul.step(letter)
        try:
            self.cache.step_in_cache(letter, out)
        except RepeatedNonDeterministicError:
            print(Fore.RED + "Non-determinism in step execution detected.")
            logger.log(Fore.RED + "Non-determinism in step execution detected.")
            self.non_det_step_counter += 1
            raise
        
        return out



def get_error_info(cache: FailSafeCacheSUL):
    """
    Create error statistics.
    """

    error_info = {
        'non_det_query': cache.non_det_query_counter,
        'non_det_step': cache.non_det_step_counter,
    }
    return error_info


def print_error_info(cache: FailSafeCacheSUL):
    """
    Print error statistics.
    """
    error_info = get_error_info(cache)
  
    print('-----------------------------------')
    print('Non-determinism in learning: {}'.format(error_info['non_det_query']))
    print('Non-determinism in equivalence check: {}'.format(error_info['non_det_step']))
    print('-----------------------------------')

    logger.error('-----------------------------------')
    logger.error('Non-determinism in learning: {}'.format(error_info['non_det_query']))
    logger.error('Non-determinism in equivalence check: {}'.format(error_info['non_det_step']))
    logger.error('-----------------------------------')