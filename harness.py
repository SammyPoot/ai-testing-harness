import json
from elasticsearch import Elasticsearch

HOST = 'localhost'
PORT = 9200
USER = 'user'
SECRET = 'secret'
SCHEME = 'https'

def make_query(input, classification_filter = false, range_km = false, lat = 50.705948, lon = -3.5091076):
    input_uc = input.upper
    classification_filter_uc = classification_filter.upper

    paf_filter = {'match': {'paf.buildingName': {'query': input_uc, 'fuzziness': '1'}}}

    nisra_filter = {'match': {'nisra.buildingName': {'query': input_uc, 'fuzziness': '1'}}}

    pao_filter = {
        'match': {
            'lpi.paoText': {
                'query': input_uc,
                'fuzziness': '1',
                'minimum_should_match': '-45%'
            }
        }
    }

    if (classification_filter):
        classification_filter_filters = [{'terms': {'classificationCode': [classification_filter_uc]}}]
    else:
        classification_filter_filters = []

    if (range_km):
        geo_filters = [{'geo_distance': {'distance': range_km.to_string + 'km', 'lpi.location': [lon, lat]}}]
    else:
        geo_filters = []

    filters = classification_filter_filters + geo_filters

    welsh_split_synonyms_analyzer_outer = {
        'query': input_uc,
        'analyzer': 'welsh_split_synonyms_analyzer',
        'boost': 1,
        'minimum_should_match': '-40%',
    }

    input_uc_matcher = {'query': input_uc, 'boost': 0.2, 'fuzziness': '0'}

    query = {
        'version': true,
        'query': {
            'dis_max': {
                'tie_breaker': 1,
                'queries': [
                    {'bool': {
                        'should': [
                            {'dis_max': {
                                'tie_breaker': 0,
                                'queries': [
                                    {'constant_score': {'filter': paf_filter, 'boost': 2.5}},
                                    {'constant_score': {'filter': nisra_filter, 'boost': 2.5}},
                                    {'constant_score': {'filter': pao_filter, 'boost': 2.5}},
                                ]
                            }}
                        ],
                        'filter': filters,
                        'minimum_should_match': '-40%'
                    }},
                    {'bool': {
                        'must': [
                            {'dis_max': {
                                'tie_breaker': 0,
                                'queries': [
                                    {'match': {'lpi.nagAll': welsh_split_synonyms_analyzer_outer}},
                                    {'match': {'nisra.nisraAll': welsh_split_synonyms_analyzer_outer}},
                                    {'match': {'paf.pafAll': welsh_split_synonyms_analyzer_outer}},
                                ]
                            }},
                        ],
                        'should': [
                            {'dis_max': {
                                'tie_breaker': 0,
                                'queries': [
                                    {'match': {'lpi.nagAll.bigram': input_uc_matcher}},
                                    {'match': {'nisra.nisraAll.bigram': input_uc_matcher}},
                                    {'match': {'paf.pafAll.bigram': input_uc_matcher}},
                                ]
                            }},
                        ],
                        'filter': filters,
                        'boost': 0.075
                    }},
                ]
            }
        },
        'from': 0,
        'size': 0,
        'sort': [{'_score': {'order': 'desc'}}, {'uprn': {'order': 'asc'}}],
        'track_scores': true
    }

    return query

def do_query(options):
    es = Elasticsearch([HOST], http_auth = (USER, SECRET), scheme = SCHEME, port = PORT)

    query = make_query(*options)
    print(json.dumps(query))
    results = es.search(index = 'test-index', body = query)
    print('Got %d Hits:' % results['hits']['total']['value'])
    for hit in results['hits']['hits']:
        print('%(timestamp)s %(author)s: %(text)s' % hit['_source'])
