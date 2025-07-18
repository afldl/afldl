import random
import constant

from learning.Errors import ConnectionError, RepeatedNonDeterministicError
from aalpy.base.SUL import SUL
from aalpy.base import Oracle
from time import sleep
from DBhelper import *
import utils,logging
###
# The code used in this file is copied from the AALpy project:
# https://github.com/DES-Lab/AALpy
#
# Following file/class has been copied:
# -- aalpy/oracles/StatePrefixEqOracle.py
#
# Adaptions to the existing code have been made:
# -- check for non-determinism
# -- check for connection errors
#
#
###

logger = logging.getLogger('model learning')

class StatePrefixOracleFailSafe(Oracle):

    MAX_CEX_ATTEMPTS = 5

    def __init__(self, alphabet: list, sul: SUL, walks_per_state=10, walk_len=30, depth_first=False, database=''):
        super().__init__(alphabet, sul)
        self.walks_per_state = walks_per_state
        self.steps_per_walk = walk_len
        self.depth_first = depth_first
        self.freq_dict = dict()
        self.dbhelper = DBhelper(database)

    def repeat_query(self, hypothesis, input_sequence):
        
        non_det_attempts = 0
        cex_found_counter = 0
        while non_det_attempts < constant.NON_DET_ERROR_ATTEMPTS:
            self.reset_hyp_and_sul(hypothesis)
            for input in input_sequence:
                out_hyp = hypothesis.step(input)
                self.num_steps += 1
                out_sul = self.sul.step(input)

                if out_sul != out_hyp:
                    cex_found_counter += 1
                    if cex_found_counter == self.MAX_CEX_ATTEMPTS:
                        return True
                    break
            
            non_det_attempts += 1

        return False

    def find_cex(self, hypothesis):
        print('start to find counterexample' + '='*100)
        logger.info(utils.logger_str(str('start to find counterexample' + '='*100)))
        states_to_cover = []
        for state in hypothesis.states:
            if state.prefix not in self.freq_dict.keys():
                self.freq_dict[state.prefix] = 0

            states_to_cover.extend([state] * (self.walks_per_state - self.freq_dict[state.prefix]))

        if self.depth_first:
            # reverse sort the states by length of their access sequences
            # first do the random walk on the state with longest access sequence
            states_to_cover.sort(key=lambda x: len(x.prefix), reverse=True)
        else:
            random.shuffle(states_to_cover)
        
        for state in states_to_cover:
            logger.info(utils.logger_str('*'*100))
            logger.info(utils.logger_str('current state : ' + str(state.state_id)))
            self.freq_dict[state.prefix] += 1

            non_det_attempts = 0
            
            suffix_buf = ()
            for _ in range(self.steps_per_walk):
                suffix_buf += (random.choice(self.alphabet),)
            
            logger.info(utils.logger_str('prefix : ' + str(state.prefix)))
            logger.info(utils.logger_str('suffix : ' + str(suffix_buf)))
            results_in_db_str = self.dbhelper.execute_query(str(state.prefix + suffix_buf))
            if results_in_db_str:
                logger.info(utils.logger_str('found in sqlite : ' + results_in_db_str))
                results_in_db = utils.str2list(results_in_db_str)
                hypothesis.reset_to_initial()
                query = state.prefix + suffix_buf
                out_hyp = ''
                out_hyps = []
                out_suls = []
                current_query = ()
                for i in range(len(query)):
                    current_query += query[i:i+1]
                    out_hyp = hypothesis.step(query[i])
                    out_hyps.append(out_hyp)
                    out_sul = results_in_db[i]
                    out_suls.append(out_sul)
                    if out_sul != out_hyp:
                        logger.info(utils.logger_str('found counterexample : ' + str(current_query)))
                        logger.info(utils.logger_str('out_hyps : ' + str(out_hyps)))
                        logger.info(utils.logger_str('out_suls : ' + str(out_suls)))
                        return current_query
                continue
            
            
            while non_det_attempts < constant.NON_DET_ERROR_ATTEMPTS:

                try:
                    is_prefix_consistent = True
                    self.reset_hyp_and_sul(hypothesis)
                    out_sul = ''
                    out_suls = []
                    out_hyp = ''
                    out_hyps = []
                    prefix = state.prefix
                    for p in prefix:
                        self.num_steps += 1
                        out_hyp = hypothesis.step(p)
                        out_hyps.append(out_hyp)
                        out_sul = self.sul.step(p)
                        out_suls.append(out_sul)
                        if out_sul != out_hyp:
                            non_det_attempts += 1
                            is_prefix_consistent = False
                            break
                    if not is_prefix_consistent:
                        continue
                            
                    suffix = ()
                    for i in range(len(suffix_buf)):
                        suffix += suffix_buf[i:i+1]
                        self.num_steps += 1
                        out_sul = self.sul.step(suffix[-1])
                        out_suls.append(out_sul)
                        out_hyp = hypothesis.step(suffix[-1])
                        out_hyps.append(out_hyp)
                        
                        if out_sul != out_hyp:
                            reproducable_cex = self.repeat_query(hypothesis, prefix + suffix)
                            if reproducable_cex:
                                logger.info(utils.logger_str('found counterexample : ' + str(prefix + suffix)))
                                logger.info(utils.logger_str('out_hyps : ' + str(out_hyps)))
                                logger.info(utils.logger_str('out_suls : ' + str(out_suls)))
                                self.dbhelper.insert_query(str(prefix + suffix), str(out_suls))
                                logger.info(utils.logger_str('insert to database'))

                                return prefix + suffix
                    self.dbhelper.insert_query(str(prefix + suffix), str(out_suls)) 
                    logger.info(utils.logger_str('insert to database'))

                    break

                except RepeatedNonDeterministicError:
                    non_det_attempts += 1
                    sleep(1)
                    if non_det_attempts == constant.NON_DET_ERROR_ATTEMPTS:
                        raise
                    
        return None