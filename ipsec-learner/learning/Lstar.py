from aalpy.learning_algs import run_Lstar
import sys
from pesp4.IKESUL import *
import DBhelper
import utils
from learning.Errors import NonDeterministicError
import logging

logger = logging.getLogger('model learning')



def ju_run_Lstar(alphabet: list, sul, eq_oracle, automaton_type,db_path,max_query = 5, samples=None,
              closing_strategy='shortest_first', cex_processing='rs',
              e_set_suffix_closed=False, all_prefixes_in_obs_table=True,
              max_learning_rounds=None, cache_and_non_det_check=True, return_data=False, print_level=2):
    
    while True:
        try:
            learned_model = run_Lstar(alphabet, sul, eq_oracle, automaton_type='mealy', cache_and_non_det_check=False, print_level=3)
            return learned_model
        except NonDeterministicError as e:
            # TODO: 因为有的设备会一直重放一些包，导致学不出来，所以加上这个策略
            if (e.expected_outputs[-1],e.outputs[-1]) == ('No_response','Other'):
                continue
                
            
            print(f"\033[31m{'#'*80}\033[0m")
            print('try to find most common respose')
            querys = e.querys
            expected_outputs = e.expected_outputs
            print(f'querys:{querys}')
            print(f'expected_outputs:{expected_outputs}')
            print(f'outputs:{e.outputs}')

            
            logger.warning(utils.logger_str(f"\033[31m{'#'*80}\033[0m"))
            logger.warning(utils.logger_str('try to find most common respose'))
            querys = e.querys
            expected_outputs = e.expected_outputs
            logger.warning(utils.logger_str(f'querys:{querys}'))
            logger.warning(utils.logger_str(f'expected_outputs:{expected_outputs}'))
            logger.warning(utils.logger_str(f'outputs:{e.outputs}'))
            # sys.exit()

            most_common_respose = utils.get_most_respose(sul,querys,max_query)
            print(f'querys:{querys}')
            print(f'expected_outputs:{expected_outputs}')
            print(f'most_common_respose:{most_common_respose}')
            logger.warning(utils.logger_str(f'querys:{querys}'))
            logger.warning(utils.logger_str(f'expected_outputs:{expected_outputs}'))
            logger.warning(utils.logger_str(f'most_common_respose:{most_common_respose}'))
            if expected_outputs != most_common_respose:
                if most_common_respose[-1] == 'No_response' and (expected_outputs[-1] != 'Other' or expected_outputs[-1] !=  'Plain_response'):
                    print('请检测设备活性')
                    logger.warning(utils.logger_str('请检测设备活性'))
                    sys.exit()
                else:
                    pass
                    # print('111111111')
                logger.warning(utils.logger_str('try to delete wrong respose in db'))
                print('try to delete wrong respose in db')
                db = DBhelper.DBhelper(db_path)
                db.clean_db(querys,most_common_respose)
                logger.warning(utils.logger_str('try to clean cache tree'))
                print('try to clean cache tree')
                sul.clean_cache()
            logger.warning(utils.logger_str(f"\033[31m{'#'*80}\033[0m")   )     
            print(f"\033[31m{'#'*80}\033[0m")        
        # except Exception as e:
        #     print(e)
        #     sys.exit()
    

