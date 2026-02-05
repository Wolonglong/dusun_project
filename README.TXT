<1> source ./env.sh

<2> mk-create-project.sh

<3> mk-cp-file.sh


#需要把公钥放到github
cat ~/.ssh/id_ed25519.pub
#绑定远程仓
git remote set-url origin git@github.com:Wolonglong/dusun_project.git
git remote -v
#上传代码
git push -u origin main
