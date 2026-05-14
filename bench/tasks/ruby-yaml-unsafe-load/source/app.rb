require 'yaml'
require 'sinatra'

post '/import' do
  data = YAML.unsafe_load(request.body.read)
  data.inspect
end

post '/restore' do
  Marshal.load(Base64.decode64(params[:state]))
end

post '/legacy' do
  YAML.load(request.body.read)
end

get '/safe-load' do
  YAML.safe_load(File.read('config/settings.yml'))
end

get '/marshal-internal' do
  Marshal.dump({ user: current_user })
end
