import AsyncStorage from '@react-native-async-storage/async-storage';

const key = '@tokenKeycloak';

class StorageToken {
  public async recuverToken(): Promise<any> {
    const response = await AsyncStorage.getItem(key);
    return response;
  }
  public async saveToken(value: any): Promise<void> {
    await AsyncStorage.setItem(key, JSON.stringify(value));
  }
  public async cleanToken(): Promise<void> {
    await AsyncStorage.removeItem(key);
  }
}

export default StorageToken;
