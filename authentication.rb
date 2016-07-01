def index
    access_key = 'YOUR_ACCESS_KEY'
    secret_key = 'YOUR_SECRET_KEY'
    time = Time.now.utc
    date_stamp = time.strftime("%Y%m%d")
    region_name = 'ap-south-1'
    key_date    = hmac_digest('sha256', "AWS4" + secret_key, date_stamp)
    key_region  = hmac_digest('sha256', key_date, region_name)
    key_service = hmac_digest('sha256', key_region, 's3')
    key_signing = hmac_digest('sha256', key_service, "aws4_request")
    algorithm = 'AWS4-HMAC-SHA256'
    amzdate = time.strftime('%Y%m%dT%H%M%SZ')
    credential_scope = access_key + '/' + date_stamp + '/ap-south-1/s3/aws4_request'
    policy = generate_policy(credential_scope, algorithm, amzdate)
    signature = OpenSSL::HMAC.hexdigest('sha256', key_signing, policy)
    render json: { policy: policy, signature: signature, key: access_key, date: amzdate, credentials: credential_scope, algorithm: algorithm }
  end

  def generate_policy(credential_scope, algorithm, amzdate)
    Base64.encode64({
      'expiration' => (Time.now + (60 * 60 * 24 * 365 * 30)).strftime('%Y-%m-%dT%H:%M:%SZ'), # 30 years from now
      'conditions' => [
        { 'bucket' => 'adcreation-m' },
        { 'acl' => 'public-read' },
        ['starts-with', '$key', ''],
        ['starts-with', '$Content-Type', ''],
        { 'success_action_status' => '201' },
        { 'x-amz-credential' => credential_scope },
        { 'x-amz-algorithm' => algorithm },
        { 'x-amz-date' => amzdate },
        ['content-length-range', 0, 256000000]
      ]
    }.to_json).delete("\n")
  end

  def hmac_digest(digest, key, data)
    OpenSSL::HMAC.digest(digest, key, data)
  end
