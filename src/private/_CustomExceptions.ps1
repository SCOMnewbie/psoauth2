class TokenExpiredException : System.Exception {
    TokenExpiredException ([string] $Message) : base($Message){
    }
}

class TokenVersionValidationFailedException : System.Exception {
    TokenVersionValidationFailedException ([string] $Message) : base($Message){
    }
}

class TokenAudienceValidationFailedException : System.Exception {
    TokenAudienceValidationFailedException ([string] $Message) : base($Message){
    }
}

class TokenSignatureValidationFailedException : System.Exception {
    TokenSignatureValidationFailedException ([string] $Message) : base($Message){
    }
}

class TokenAzpacrValidationFailedException : System.Exception {
    TokenAzpacrValidationFailedException ([string] $Message) : base($Message){
    }
}

class TokenAzpValidationFailedException : System.Exception {
    TokenAzpValidationFailedException ([string] $Message) : base($Message){
    }
}

class TokenUnusableException : System.Exception {
    TokenUnusableException ([string] $Message) : base($Message){
    }
}