const textToSpeech = require('@google-cloud/text-to-speech');
const fs = require('fs');

// Instantiate the Text-to-Speech client
const client = new textToSpeech.TextToSpeechClient();

async function convertTextToSpeechWithGoogleCloud(text) {
  try {
    const request = {
      input: { text: text },
      voice: { languageCode: 'en-US', ssmlGender: 'NEUTRAL' },
      audioConfig: { audioEncoding: 'MP3' },
    };

    const [response] = await client.synthesizeSpeech(request);
    console.log('Audio content:', response.audioContent);
  } catch (error) {
    console.error('Error during text-to-speech conversion:', error);
    throw error;
  }
}


module.exports = { convertTextToSpeechWithGoogleCloud };
