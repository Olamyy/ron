# ron

A wrapper around AWS CDK for generating AWS resources from yaml specifications


## Installing ron

`pip install git+https://github.com/Olamyy/ron.git`

## Using ron

To generate a CloudFormation template, ron needs a yaml needs a yaml specification to work with. 
A sample specification is available [here](https://bitbucket.org/languageio/prod-translation-quality-evaluation-pipeline/src/dev/deploy/config/one_container.yaml)

To generate a CF stack from this yaml, run ``ron generate --config prod-translation-quality-evaluation-pipeline/src/dev/deploy/config/one_container.yaml``

You can also run ``run generate`` from the root of the project and `ron` automatically picks up the yaml config.
