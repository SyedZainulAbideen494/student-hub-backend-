import sys
from youtube_transcript_api import YouTubeTranscriptApi, TranscriptsDisabled

def fetch_transcript(video_id):
    try:
        # Get the list of available transcripts
        transcript_list = YouTubeTranscriptApi.list_transcripts(video_id)
        
        # Try fetching English transcript first
        try:
            transcript = transcript_list.find_transcript(['en', 'en-IN'])
        except:
            # If English is not available, try another language (e.g., Hindi)
            transcript = transcript_list.find_generated_transcript(['hi', 'en-IN'])  # Fallback
        
        # Fetch transcript text
        full_text = " ".join([entry["text"] for entry in transcript.fetch()])
        
        # Ensure proper UTF-8 encoding
        sys.stdout.buffer.write(full_text.encode("utf-8"))
    
    except TranscriptsDisabled:
        print("Error: Transcripts are disabled for this video.", file=sys.stderr)
    except Exception as e:
        print("Error fetching transcript:", str(e).encode("utf-8", "ignore").decode(), file=sys.stderr)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Error: No video ID provided.", file=sys.stderr)
    else:
        fetch_transcript(sys.argv[1])
