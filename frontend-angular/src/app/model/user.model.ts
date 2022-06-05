export class UserModel {
  id!:number
  username!: string;
  roles!: Array<string>;
  get roleT(): Array<string> {
    return this.roles;
  }
}
