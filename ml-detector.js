// Real ML-Powered Phishing Detector using Hugging Face API
console.log('🤖 ML-Powered Phishing Detector v7.0 loading...');

class PhishingMLDetector {
  constructor() {
    this.modelLoaded = false;
    this.apiKey = null;
    
    // Using a model specifically trained for phishing detection
    this.apiUrl = 'https://api-inference.huggingface.co/models/mrm8488/bert-tiny-finetuned-sms-phishing-detection';
    
    console.log('✅ PhishingMLDetector v7.0 initialized');
  }

  async loadModel() {
    console.log('🤖 Initializing ML API connection...');
    
    // Load API key from Chrome storage
    await this.loadApiKey();
    
    if (!this.apiKey || this.apiKey === '') {
      console.warn('⚠️ NO API KEY SET!');
      console.log('📝 Get your FREE key: https://huggingface.co/settings/tokens');
      console.log('💡 Using fallback detection until you add your API key');
      console.log('🔧 Add your key in the extension popup settings');
      this.modelLoaded = false;
    } else {
      // Test API connection
      try {
        console.log('🔄 Testing API connection...');
        await this.testAPIConnection();
        this.modelLoaded = true;
        console.log('✅ ML API ready! Using real phishing detection model');
        console.log('🔑 API Key configured: ' + this.apiKey.substring(0, 10) + '...');
      } catch (error) {
        console.error('❌ API connection failed:', error.message);
        console.log('⚠️ Using fallback detection');
        this.modelLoaded = false;
      }
    }
  }

  async loadApiKey() {
    return new Promise((resolve) => {
      chrome.storage.local.get(['huggingface_api_key'], (result) => {
        this.apiKey = result.huggingface_api_key || null;
        resolve();
      });
    });
  }

  async testAPIConnection() {
    const response = await fetch(this.apiUrl, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${this.apiKey}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        inputs: "Test message",
        options: { wait_for_model: true }
      })
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`API Error: ${response.status} - ${errorText}`);
    }
  }

  async analyzeEmail(emailData) {
    try {
      const { sender = '', subject = '', snippet = '' } = emailData;
      const emailText = `From: ${sender}\nSubject: ${subject}\n${snippet}`;
      
      console.log('🔍 Analyzing:', subject?.substring(0, 40) || 'No subject');
      
      let mlScore = 0;
      let mlConfidence = 0;
      let usedML = false;

      // Try ML API first
      if (this.modelLoaded && this.apiKey) {
        try {
          const mlResult = await this.getMLPrediction(emailText);
          mlScore = mlResult.score;
          mlConfidence = mlResult.confidence;
          usedML = true;
          console.log(`   🤖 ML Result: ${mlResult.label} (${mlConfidence.toFixed(2)}% confident)`);
        } catch (error) {
          console.warn('⚠️ ML API call failed, using fallback:', error.message);
          mlScore = this.getFallbackScore(emailData);
        }
      } else {
        mlScore = this.getFallbackScore(emailData);
      }

      // Determine risk level based on ML score
      let riskLevel = 'low';
      let confidence = 'Appears safe';
      let icon = '✓';
      
      if (mlScore >= 65) {
        riskLevel = 'high';
        confidence = usedML ? 
          `🤖 AI detected phishing (${mlConfidence.toFixed(0)}% confidence)` : 
          '🚨 High risk detected';
        icon = '⚠️';
      } else if (mlScore >= 35) {
        riskLevel = 'medium';
        confidence = usedML ? 
          `⚠️ AI flagged as suspicious (${mlConfidence.toFixed(0)}% confidence)` : 
          '⚠️ Potentially suspicious';
        icon = '⚡';
      } else {
        confidence = usedML ? 
          `✓ AI verified safe (${(100 - mlConfidence).toFixed(0)}% confidence)` : 
          '✓ Appears safe';
      }

      const reasons = this.generateReasons(mlScore, emailData, usedML);
      
      const result = {
        score: Math.round(mlScore),
        riskLevel,
        confidence,
        details: {
          mlScore: Math.round(mlScore),
          mlConfidence: Math.round(mlConfidence),
          usedAI: usedML
        },
        reasons
      };
      
      console.log(`📊 Final: ${Math.round(mlScore)}/100 - ${riskLevel.toUpperCase()} ${icon}`);
      
      return result;
    } catch (error) {
      console.error('❌ Error in analyzeEmail:', error);
      return this.getErrorResult();
    }
  }

  async getMLPrediction(text) {
    try {
      // Try direct fetch first (works in content script context)
      const response = await fetch(this.apiUrl, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${this.apiKey}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          inputs: text.substring(0, 500), // Limit text length
          options: { 
            wait_for_model: true,
            use_cache: false
          }
        })
      });

      if (!response.ok) {
        throw new Error(`API returned ${response.status}`);
      }

      const result = await response.json();
      console.log('   🔬 Raw API response:', result);

      return this.parseMLResult(result);

    } catch (error) {
      console.error('❌ ML API Error:', error);
      
      // Try background service worker as fallback
      try {
        console.log('🔄 Trying background service worker...');
        const bgResult = await new Promise((resolve, reject) => {
          chrome.runtime.sendMessage(
            { action: 'analyzeWithAPI', apiKey: this.apiKey, text: text },
            (response) => {
              if (chrome.runtime.lastError) {
                reject(new Error(chrome.runtime.lastError.message));
              } else if (response.success) {
                resolve(response.data);
              } else {
                reject(new Error(response.error));
              }
            }
          );
        });
        
        console.log('✅ Background worker succeeded');
        return this.parseMLResult(bgResult);
      } catch (bgError) {
        console.error('❌ Background worker also failed:', bgError);
        throw error; // Throw original error
      }
    }
  }

  parseMLResult(result) {
    // Parse result - format: [[{label: "ham/spam", score: 0.99}]]
    let isPhishing = false;
    let confidence = 0;

    if (Array.isArray(result) && result.length > 0) {
      // Handle nested array format
      const predictions = Array.isArray(result[0]) ? result[0] : result;
      
      // Find phishing/spam prediction
      const phishingPred = predictions.find(p => 
        p.label && (
          p.label.toLowerCase().includes('spam') || 
          p.label.toLowerCase().includes('phishing') ||
          p.label.toLowerCase().includes('smishing') ||
          p.label === 'LABEL_1' || 
          p.label === '1'
        )
      );

      if (phishingPred) {
        isPhishing = true;
        confidence = phishingPred.score * 100;
      } else {
        // If no phishing label, check for ham/safe
        const safePred = predictions.find(p => 
          p.label && (
            p.label.toLowerCase().includes('ham') || 
            p.label.toLowerCase().includes('safe') ||
            p.label === 'LABEL_0' ||
            p.label === '0'
          )
        );
        
        if (safePred) {
          isPhishing = false;
          confidence = (1 - safePred.score) * 100; // Invert for phishing score
        }
      }
    }

    // Convert to 0-100 phishing score
    const phishingScore = isPhishing ? confidence : (100 - confidence);
    
    return {
      score: phishingScore,
      confidence: confidence,
      label: isPhishing ? 'PHISHING' : 'SAFE'
    };
  }

  getFallbackScore(emailData) {
    // Smart fallback when API unavailable
    const { sender = '', subject = '', snippet = '' } = emailData;
    const text = `${sender} ${subject} ${snippet}`.toLowerCase();
    
    let score = 0;

    // Critical phishing phrases (30 points each)
    const criticalPhrases = [
      'verify your account', 'account suspended', 'confirm your identity',
      'urgent action required', 'unusual activity', 'click here immediately',
      'reset your password', 'suspended unless', 'will be closed',
      'verify identity', 'confirm ownership', 'reactivate your account'
    ];
    
    criticalPhrases.forEach(phrase => {
      if (text.includes(phrase)) score += 30;
    });

    // High-risk keywords (15 points each)
    const highRisk = ['suspended', 'verify', 'urgent', 'immediately', 'confirm', 
                      'locked', 'expired', 'limited', 'unusual', 'unauthorized'];
    highRisk.forEach(word => {
      if (text.includes(word)) score += 15;
    });

    // Prize scams (40 points)
    if (text.match(/won|prize|lottery|million|winner|congratulations/)) {
      score += 40;
    }

    // Money mentions (20 points)
    if (text.match(/\$[\d,]+|\d+\s*(dollars|usd|€|£)/i)) score += 20;

    // Threats (25 points)
    if (text.match(/will be (closed|terminated|suspended|locked)|lose access|permanently/)) {
      score += 25;
    }

    // Generic greetings (15 points)
    if (text.match(/dear (customer|user|member|sir|madam)/)) score += 15;

    // Suspicious domains (35 points)
    if (sender.match(/\.tk|\.ml|\.ga|\.xyz|\.top|tempmail|guerrillamail|10minutemail/i)) {
      score += 35;
    }

    // URL shorteners (20 points)
    if (text.match(/bit\.ly|tinyurl|goo\.gl|ow\.ly|t\.co/)) score += 20;

    // Requests for sensitive info (30 points)
    if (text.match(/social security|ssn|password|credit card|bank account|routing number/i)) {
      score += 30;
    }

    // Poor grammar indicators (10 points)
    if (text.match(/dear sir\/madam|kindly|needful|revert back/)) score += 10;

    return Math.min(score, 100);
  }

  generateReasons(score, emailData, usedML) {
    const reasons = [];
    const { sender = '', subject = '', snippet = '' } = emailData;
    const text = `${sender} ${subject} ${snippet}`.toLowerCase();

    if (usedML) {
      if (score >= 65) {
        reasons.push('🤖 AI model detected phishing patterns');
      } else if (score >= 35) {
        reasons.push('🤖 AI flagged as suspicious');
      } else {
        reasons.push('🤖 AI verified as safe');
      }
    } else {
      reasons.push('⚙️ Using pattern-based detection (no API key)');
    }

    // Add specific reasons based on content
    if (text.includes('verify') || text.includes('confirm')) {
      reasons.push('🔒 Requests verification/confirmation');
    }

    if (text.includes('suspended') || text.includes('locked')) {
      reasons.push('⚠️ Claims account is suspended');
    }

    if (text.includes('urgent') || text.includes('immediately')) {
      reasons.push('⚡ Uses urgency pressure');
    }

    if (text.match(/won|prize|lottery/)) {
      reasons.push('🎰 Prize/lottery indicators');
    }

    if (text.match(/\$/)) {
      reasons.push('💰 Money amount mentioned');
    }

    if (text.match(/click here|click now/)) {
      reasons.push('🔗 Click-bait language');
    }

    if (text.match(/dear (customer|user)/)) {
      reasons.push('👤 Generic greeting');
    }

    if (sender.match(/\.tk|\.ml|\.ga|tempmail/i)) {
      reasons.push('🚨 Suspicious sender domain');
    }

    if (text.match(/bit\.ly|tinyurl/)) {
      reasons.push('🔗 URL shortener detected');
    }

    if (text.match(/password|credit card|ssn/i)) {
      reasons.push('🔐 Requests sensitive information');
    }

    if (reasons.length <= 1) {
      reasons.push('✓ No major red flags detected');
    }

    return reasons.slice(0, 5);
  }

  getErrorResult() {
    return {
      score: 50,
      riskLevel: 'medium',
      confidence: 'Unable to analyze',
      details: { mlScore: 50, mlConfidence: 0, usedAI: false },
      reasons: ['⚠️ Analysis error - treat with caution']
    };
  }
}

// Register globally
try {
  window.PhishingMLDetector = PhishingMLDetector;
  console.log('✅ ML-Powered PhishingMLDetector v7.0 registered successfully');
  console.log('');
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log('🔧 TO USE REAL AI MODEL:');
  console.log('1. Click extension icon');
  console.log('2. Click "⚙️ Settings"');
  console.log('3. Add your Hugging Face API key');
  console.log('   Get free key: https://huggingface.co/settings/tokens');
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log('');
} catch (error) {
  console.error('❌ Error registering:', error);
}
