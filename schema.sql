-- Users Table
CREATE TABLE users (
    user_id SERIAL PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    hashed_password VARCHAR(255) NOT NULL,
    username VARCHAR(50) UNIQUE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- AI Generations Table
CREATE TABLE ai_generations (
    generation_id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(user_id) ON DELETE CASCADE,
    generation_type VARCHAR(50) NOT NULL, -- e.g., 'avatar', 'filter', 'face_swap'
    input_image_url VARCHAR(255) NOT NULL,
    output_image_url VARCHAR(255),
    generation_parameters JSONB, -- Store filter settings, etc.
    status VARCHAR(50) DEFAULT 'pending', -- e.g., 'pending', 'processing', 'completed', 'failed'
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_ai_generations_user_id ON ai_generations (user_id);

-- User Profiles Table (Optional, for storing user preferences)
CREATE TABLE user_profiles (
    profile_id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(user_id) ON DELETE CASCADE,
    profile_data JSONB, -- Store preferences like preferred styles, etc.
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE UNIQUE INDEX idx_user_profiles_user_id ON user_profiles (user_id);

-- API Usage Logs (for monitoring and rate limiting)
CREATE TABLE api_usage_logs (
    log_id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(user_id) ON DELETE SET NULL, -- Allow anonymous usage
    endpoint VARCHAR(255) NOT NULL,
    request_timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    request_body JSONB,
    response_code INTEGER,
    processing_time_ms INTEGER
);

CREATE INDEX idx_api_usage_logs_user_id ON api_usage_logs (user_id);
CREATE INDEX idx_api_usage_logs_endpoint ON api_usage_logs (endpoint);
