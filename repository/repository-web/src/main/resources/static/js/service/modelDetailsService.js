repository.factory('ModelDetailsService',['$http','$q','$location',function($http, $q, $location){

    var ATTACHMENT_URL = './api/v1/attachments/';

    var factory = {
        uploadAttachment: uploadAttachment
    };

    return factory;

    function uploadAttachment(passingValue) {
         var deferred = $q.defer();

         $http.put(ATTACHMENT_URL + passingValue.modelId,
                    passingValue.payload,
                        {
         					transformRequest: angular.identity,
         					headers: {
         						'Content-Type': undefined
         					}
         				}
         			)
                .then(
                    function(response) {
                        deferred.resolve(response.data);
                    },
                    function(errResponse){
                        deferred.reject(errResponse);
                    }
                );
          return deferred.promise;
    }
}]);