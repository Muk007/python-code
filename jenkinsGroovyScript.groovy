
import groovy.json.JsonSlurper
try {
    def command = "aws s3 cp --region us-west-2 s3://lr-jenkins-backup/ansible-inventory.json /tmp/inventory.json"
    def output = command.execute()
    output.waitFor()
    def error = output.err.text
    def regions = output.text.tokenize().toUnique()
    if (error) {
        return [error]
    } else {
        def inputFile = new File("/tmp/inventory.json")
        def InputJSON = new JsonSlurper().parse(inputFile)
        assert InputJSON instanceof Map
        region_keyset   =  InputJSON.keySet()
        regions         = region_keyset as ArrayList
        if (regions.size()>0) {
            regions.set(0,regions.get(0)+":selected")
        }
        return regions
    }
} catch (Exception e) {
    return [bucket_name+"==>"+e.getMessage()]
}

###################################################################################################################################


import groovy.json.JsonSlurper
try {
    if (binding.variables.get('Regions')!=null) {
        def selected_regions = binding.variables.get('Regions').tokenize( ',' )
        def inputFile = new File("/tmp/inventory.json")
        def InputJSON = new JsonSlurper().parse(inputFile)
        instances = []
        for (selected_region in selected_regions) {
            region_instances = InputJSON[selected_region]
            for (instance in region_instances) {
                instances.add(instance.instance_name)
            }
        }
        return instances
    } else {
        return ["None"]
    }
} catch (Exception e) {
    return ["==>"+e.getMessage()]
}

